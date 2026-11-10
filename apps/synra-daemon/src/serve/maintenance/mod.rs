//! Long-lived maintenance loops for claim refresh, retention and late replies.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::args::{ClaimFile, refresh_claim};
use crate::runtime::now_ms;

mod retention;

use retention::{collect_loop, gc_task};

/// How often the claim is refreshed.
///
/// Read from the daemon's own constant rather than written here, because the stale-after window and the interval are two
/// halves of one decision: an interval that outlived the window would make a healthy daemon look dead to the next start.
const HEARTBEAT_MS: u64 = crate::HEARTBEAT_INTERVAL_MS;

/// Starts the maintenance loops the daemon runs for its whole life, and returns what to join on shutdown.
///
/// Why `run_task` rather than `std::thread::spawn`.
///
/// Both loops were bare spawns, and a bare spawn is a task whose death is indistinguishable from its silence: a panic
/// unwinds, the thread stops, the daemon serves on, and nothing records anything. `run_task` owns the registration, the
/// cancellation token, the restart decision and the record — **and it already existed and was already used** for the
/// transport listener and for discovery. The fix was to use it, not to write a second one beside it.
///
/// A task that will not start leaves nothing to join: the daemon serves without it rather than refusing to run, which is the
/// choice the two services make as well.
/// One supervised loop's handle, when it started.
pub(super) type LoopHandle = Option<std::thread::JoinHandle<()>>;

pub(super) fn start_loops(
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    db: &Arc<Mutex<synra_store::SynraDb>>,
    lock_path: &std::path::Path,
    host: &Arc<Mutex<synra_core::Host>>,
    data_dir: &std::path::Path,
) -> (LoopHandle, LoopHandle, LoopHandle) {
    use synra_core::supervisor::{TaskId, run_task};

    // ★ Answers that could not be delivered when they were produced are retried here, on a timer, because the producer is
    // a connection thread and a connection thread must not wait for a device that may be gone. Thirty seconds is short
    // enough that a peer's restart is noticed and long enough that a permanently gone peer costs two dials a minute.
    let retrier = {
        let host = Arc::clone(host);
        let data_dir = data_dir.to_path_buf();
        let id = TaskId::new("late.retry");
        match run_task(supervisor, &id, move |token| {
            late_retry_loop(token, &host, &data_dir);
            Ok(())
        }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                eprintln!("synra-daemon: the late-answer retrier did not start: {error}");
                None
            }
        }
    };

    let heartbeat = {
        // One clone for the task's body and the caller's own reference for `run_task`: the body may not hold the same
        // `Arc` the caller is borrowing in the same expression.
        let inner = Arc::clone(supervisor);
        let lock_path = lock_path.to_path_buf();
        let id = TaskId::new("heartbeat.tick");
        match run_task(supervisor, &id, move |_token| {
            heartbeat_loop(&inner, &lock_path);
            Ok(())
        }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                eprintln!("synra-daemon: the heartbeat did not start: {error}");
                None
            }
        }
    };

    let collector = {
        let inner = Arc::clone(supervisor);
        let db = Arc::clone(db);
        let id = TaskId::new("gc.collect");
        match run_task(supervisor, &id, move |_token| {
            collect_loop(&db, &inner, gc_task());
            Ok(())
        }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                eprintln!("synra-daemon: the retention sweep did not start: {error}");
                None
            }
        }
    };

    (heartbeat, collector, retrier)
}

/// Joins every supervised loop that started.
///
/// # Why a tuple rather than three calls in `serve`
///
/// Because `serve` has a complexity budget, and three "if it started, join it" branches beside the shutdown report is the
/// kind of code that pushes it over. The loops are a set: they stop together and are joined together.
pub(super) fn join_loops(loops: (LoopHandle, LoopHandle, LoopHandle)) {
    for handle in [loops.0, loops.1, loops.2].into_iter().flatten() {
        let _ = handle.join();
    }
}

/// Retries queued late answers until the supervisor asks the daemon to stop.
fn late_retry_loop(
    token: &synra_core::supervisor::Cancellation,
    host: &Arc<Mutex<synra_core::Host>>,
    data_dir: &std::path::Path,
) {
    loop {
        let summary = synra_core::listener::retry_late(host, data_dir);
        if summary.delivered > 0 || summary.dropped > 0 {
            tracing::info!(
                delivered = summary.delivered,
                failed = summary.failed,
                dropped = summary.dropped,
                "late answers were retried"
            );
        }
        if token.wait(Duration::from_secs(30)) {
            break;
        }
    }
}

/// Waits, unless the daemon is asked to stop first.
///
/// # Returns
///
/// `false` when the wait was cut short by a shutdown, so the caller can stop rather than carry on for another interval.
fn sleep_until_shutdown(
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    total: Duration,
) -> bool {
    const SLICE: Duration = Duration::from_millis(250);
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if supervisor.is_shutting_down() {
            return false;
        }
        std::thread::sleep(SLICE.min(deadline.saturating_duration_since(Instant::now())));
    }
    !supervisor.is_shutting_down()
}

/// Refreshes the claim on an interval until asked to stop.
///
/// # ★ Why this asks the supervisor to stop rather than setting a flag
///
/// Because there is one shutdown path now. The loop used to clear a process-wide `AtomicBool` that four other places read,
/// which meant "the claim is gone" and "the user pressed Ctrl-C" and "a task failed" all arrived as the same unlabelled
/// event — and the transport loop had already been written with the polarity backwards once, which is what an untyped
/// boolean shared by five readers invites.
///
/// [`synra_core::supervisor::Supervisor::begin_shutdown`] is that one path: it cancels every task's token, and the two services stop because the
/// token they were given is cancelled, not because somebody remembered to look at a flag.
///
/// # Why the claim is re-read rather than held
///
/// The file is the source of truth, and a copy held in memory would go stale the moment anything else touched it — which
/// is exactly the condition this loop exists to notice. Re-reading costs one small file per interval and makes "does
/// this process still own the directory" a question about the directory rather than about a copy of it.
fn heartbeat_loop(
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    lock_path: &std::path::Path,
) {
    while !supervisor.is_shutting_down() {
        std::thread::sleep(Duration::from_millis(HEARTBEAT_MS));

        let current = match ClaimFile::read(lock_path) {
            Ok(ClaimFile::Found(lock)) => lock,
            // No claim to refresh. Either the start-up wrote none — a daemon that never claimed the directory — or
            // another process removed it. Neither is a reason to stop serving: what a *client* needs is the socket, and
            // what the next *start* needs is the claim it will find missing and treat as a crash.
            Ok(ClaimFile::Absent) => continue,
            Err(error) => {
                eprintln!("synra-daemon: the claim could not be read, stopping: {error}");
                let _ = supervisor.begin_shutdown();
                return;
            }
        };

        // ★ Only this process's own claim is refreshed. A claim naming another process means the directory has been
        // reclaimed — another daemon is serving it — and continuing would be two daemons over one database, which is a
        // correctness problem rather than a performance one.
        if current.owner.pid != std::process::id() {
            eprintln!(
                "synra-daemon: the claim now names process {}, stopping",
                current.owner.pid
            );
            let _ = supervisor.begin_shutdown();
            return;
        }

        if let Err(error) = refresh_claim(lock_path, &current, now_ms()) {
            eprintln!("synra-daemon: the claim could not be refreshed, stopping: {error}");
            let _ = supervisor.begin_shutdown();
            return;
        }
    }
}

#[cfg(test)]
mod tests;
