//! Sending again the dispatches a restart left in flight.
//!
//! # Why the daemon needs this
//!
//! Because the window has had it since the board was made durable, and the daemon had not: it restored every intent and
//! then left a `Dispatching` one exactly as it found it. The peer is still waiting on an answer, the board says the action
//! is running, and the one process that could ask again does nothing until the 24-hour expiry. The request identifier is
//! the receiving side's idempotency key, so asking again is safe: it either runs the action once or returns the outcome
//! that already happened.
//!
//! # What this is
//!
//! The immediate pass, then the kernel's [`RetryQueue`](synra_core::intent::retry::RetryQueue): a bounded backoff that
//! survives a restart and is the same schedule the window runs. The queue lives in the kernel because both hosts need it;
//! this file is the daemon's half — the dial, the board, and the row.
//!
//! # Why it takes pieces rather than a `Runtime`
//!
//! Because the runtime is owned by the serving thread and cannot be shared; the host, the board and the database are
//! already behind `Arc`s, and those are the only parts a resend touches.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use synra_core::Host;
use synra_core::dispatch::orchestrate;
use synra_core::intent::retry::{RetryPolicy, RetryQueue};
use synra_core::intent::{Board, persist};
use synra_core::supervisor::Cancellation;
use synra_protocol::ids::{DeviceId, IntentId};
use synra_store::SynraDb;

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Dispatches this pass tried to send again.
    pub(crate) attempted: usize,
    /// Dispatches whose answer arrived and was applied.
    pub(crate) answered: usize,
    /// Dispatches that were sent and answered with nothing inside the wait.
    pub(crate) unanswered: usize,
    /// Dispatches whose send could not be made at all.
    pub(crate) failed: usize,
}

/// How one attempt ended.
enum Outcome {
    /// The answer arrived and was applied.
    Answered,
    /// The envelope went out and nothing came back inside the wait.
    Unanswered,
    /// The send could not be made at all.
    Failed,
}

/// Sends every dispatch this device left in flight, once.
pub(crate) fn resend_outstanding(
    host: &Arc<Mutex<Host>>,
    board: &Arc<Mutex<Board>>,
    db: &Arc<Mutex<SynraDb>>,
    local: DeviceId,
) -> Report {
    let now = synra_store::sqlite::now_ms();
    let pending = outbound_pairs(board, local, now);

    let mut report = Report::default();
    for (_, outbound) in pending {
        report.attempted += 1;
        match attempt(host, board, db, &outbound) {
            Outcome::Answered => report.answered += 1,
            Outcome::Unanswered => report.unanswered += 1,
            Outcome::Failed => report.failed += 1,
        }
    }
    report
}

/// The immediate pass, then the retry schedule, until cancelled.
///
/// # Why this is a loop and not a one-shot
///
/// Because §8.224's one pass only asked once, on start-up: a dispatch that could not be reached then sat until the next
/// restart or the 24-hour expiry. The queue is the same value the window runs, so the two hosts now agree on when the
/// next try is — the difference is what each does with the answer, not how often it asks.
///
/// # What it never does
///
/// It never mints a new request id and it never *fails* an intent: a send that could not be made is a fact about this
/// process's effort, not about the action. A late answer and the expiry still own the outcome.
pub(crate) fn run(
    host: &Arc<Mutex<Host>>,
    board: &Arc<Mutex<Board>>,
    db: &Arc<Mutex<SynraDb>>,
    local: DeviceId,
    cancel: &Cancellation,
    policy: RetryPolicy,
) {
    let report = resend_outstanding(host, board, db, local);
    if report.attempted > 0 {
        eprintln!(
            "synra-daemon: re-sent {} dispatch(es): {} answered, {} unanswered, {} failed",
            report.attempted, report.answered, report.unanswered, report.failed
        );
    }

    let now = synra_store::sqlite::now_ms();
    let pending = pending_ids(board, local, now);
    let rows = match db.lock().load_intent_retries() {
        Ok(rows) => rows,
        Err(error) => {
            eprintln!("synra-daemon: the stored retry schedules could not be read: {error}");
            Vec::new()
        }
    };
    let pending_set: std::collections::HashSet<IntentId> = pending.iter().copied().collect();
    let (mut queue, stale) = RetryQueue::restore(policy, &rows, &pending_set, now);
    for intent in stale {
        forget_row(db, &intent);
    }
    for id in &pending {
        persist(queue.row(*id), db, *id);
    }

    loop {
        if cancel.is_cancelled() {
            return;
        }

        let now = synra_store::sqlite::now_ms();
        for id in queue.take_due(now) {
            // The intent may have ended between the snapshot and this moment.
            let Some((_, outbound)) = outbound_pairs(board, local, now).into_iter().find(|(candidate, _)| *candidate == id)
            else {
                queue.forget(id);
                persist(queue.row(id), db, id);
                continue;
            };
            match attempt(host, board, db, &outbound) {
                Outcome::Answered => {
                    queue.forget(id);
                    persist(queue.row(id), db, id);
                }
                Outcome::Unanswered | Outcome::Failed => {
                    let more = queue.record_failure(id, synra_store::sqlite::now_ms());
                    persist(queue.row(id), db, id);
                    if !more {
                        eprintln!(
                            "synra-daemon: intent {id} was re-sent {} times without an answer; it stays dispatching until it expires",
                            policy.max_attempts
                        );
                    }
                }
            }
        }

        for id in queue.observe(pending_ids(board, local, synra_store::sqlite::now_ms()), synra_store::sqlite::now_ms()) {
            persist(queue.row(id), db, id);
        }
        let wait = queue
            .next_wait(synra_store::sqlite::now_ms())
            .min(Duration::from_secs(30))
            .max(Duration::from_millis(10));
        sleep_unless_cancelled(cancel, wait);
    }
}

/// One send, with the answer applied and written down.
fn attempt(
    host: &Arc<Mutex<Host>>,
    board: &Arc<Mutex<Board>>,
    db: &Arc<Mutex<SynraDb>>,
    outbound: &synra_core::intent::remote::Outbound,
) -> Outcome {
    match super::commands::exchange(host, outbound, true) {
        Ok(Some(reply)) => match orchestrate::apply_result(board, &reply) {
            Ok(Some(id)) => {
                checkpoint(board, db, id);
                Outcome::Answered
            }
            // A reply this device is not waiting on: the intent may have been cancelled while the answer was in flight.
            // Nothing to apply.
            Ok(None) => Outcome::Unanswered,
            Err(error) => {
                eprintln!("synra-daemon: the result could not be applied: {error}");
                Outcome::Failed
            }
        },
        Ok(None) => Outcome::Unanswered,
        Err(error) => {
            eprintln!("synra-daemon: {} could not be sent again: {error}", outbound.to);
            Outcome::Failed
        }
    }
}

/// The outstanding dispatches and the envelope each one needs.
fn outbound_pairs(
    board: &Arc<Mutex<Board>>,
    local: DeviceId,
    now_ms: i64,
) -> Vec<(IntentId, synra_core::intent::remote::Outbound)> {
    // The board is read once per pass, and the lock released before the first dial: a send blocks for up to the whole
    // wait, and a board guard held across it would make every intent command wait for the network.
    board
        .lock()
        .all()
        .into_iter()
        .filter_map(|intent| {
            orchestrate::resume(intent, local, now_ms).map(|outbound| (intent.id, outbound))
        })
        .collect()
}

/// The ids the loop would send right now.
fn pending_ids(board: &Arc<Mutex<Board>>, local: DeviceId, now_ms: i64) -> Vec<IntentId> {
    outbound_pairs(board, local, now_ms).into_iter().map(|(id, _)| id).collect()
}

/// Writes a schedule down, or removes it when the intent is no longer being retried.
fn persist(row: Option<synra_store::IntentRetryRow>, db: &Arc<Mutex<SynraDb>>, id: IntentId) {
    let outcome = {
        let db = db.lock();
        match row {
            Some(row) => db.save_intent_retry(&row),
            None => db.forget_intent_retry(&id.to_string()),
        }
    };
    if let Err(error) = outcome {
        // A schedule that did not reach the disk costs one restart's worth of backoff, not the action.
        eprintln!("synra-daemon: the retry schedule for {id} could not be written: {error}");
    }
}

/// Removes a row whose intent is no longer in flight.
fn forget_row(db: &Arc<Mutex<SynraDb>>, intent: &str) {
    if let Err(error) = db.lock().forget_intent_retry(intent) {
        eprintln!("synra-daemon: the stale retry schedule for {intent} could not be removed: {error}");
    }
}

/// Sleeps in slices, so a shutdown does not wait out a five-minute backoff.
fn sleep_unless_cancelled(cancel: &Cancellation, wait: Duration) {
    let mut left = wait;
    while !left.is_zero() {
        if cancel.is_cancelled() {
            return;
        }
        let slice = left.min(Duration::from_millis(250));
        std::thread::sleep(slice);
        left = left.saturating_sub(slice);
    }
}

/// Writes the intent's new state down.
///
/// The command path does this through `Runtime::checkpoint_intent`; a free function cannot, and the mapping it uses is the
/// kernel's (`persist::record_of`), so there is still one description of a row.
fn checkpoint(board: &Arc<Mutex<Board>>, db: &Arc<Mutex<SynraDb>>, id: IntentId) {
    let record = {
        let board = board.lock();
        persist::record_of(&board, id, synra_store::sqlite::now_ms())
    };
    let Some(record) = record else {
        return;
    };
    if let Err(error) = db.lock().save_intent(&record) {
        // The action has already happened, so this is a record a restart will not have — not a failure of the resend.
        eprintln!("synra-daemon: intent {id} was not written down: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_core::intent::{Choice, IntentSource, IntentState};
    use synra_protocol::ids::{PluginId, RequestId};

    #[test]
    fn a_dispatch_with_no_known_address_is_counted_and_left_alone() {
        // ★ The pass must not invent an address, and must not change the intent when it cannot send: "I could not reach
        // it" is not "it failed", and the 24-hour expiry or a late answer still owns the outcome.
        let dir = std::env::temp_dir().join(format!("synra-daemon-retry-{}", RequestId::new()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let runtime = crate::runtime::tests::runtime(&dir);
        let peer = DeviceId::new();
        let now = synra_store::sqlite::now_ms();
        let (id, ..) = runtime.board.lock().raise(
            IntentSource::Direct {
                plugin_id: PluginId::parse("@acme/opener").expect("a plugin id"),
                action: "open".to_owned(),
                params: serde_json::json!({}),
                target: peer,
            },
            Choice::Automatic,
            None,
            Some(RequestId::new()),
            now,
        );

        let report = resend_outstanding(
            &runtime.host,
            &runtime.board,
            &runtime.db,
            runtime.identity.device_id,
        );

        assert_eq!(report.attempted, 1);
        assert_eq!(report.failed, 1, "there is no address to dial");
        assert!(matches!(
            runtime.board.lock().get(id).map(|intent| intent.state.clone()),
            Some(IntentState::Dispatching { .. })
        ));
        drop(runtime);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_retry_loop_stops_when_it_is_cancelled() {
        // ★ The shutdown path: the loop sleeps for up to thirty seconds when nothing is pending, so it has to notice a
        // cancellation inside a slice rather than after the whole wait. A daemon that will not close is worse than one
        // that never retried.
        let dir = std::env::temp_dir().join(format!("synra-daemon-retry-loop-{}", RequestId::new()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let runtime = crate::runtime::tests::runtime(&dir);
        let host = Arc::clone(&runtime.host);
        let board = Arc::clone(&runtime.board);
        let db = Arc::clone(&runtime.db);
        let local = runtime.identity.device_id;
        let cancel = Cancellation::new();
        let token = cancel.clone();

        let handle = std::thread::spawn(move || run(&host, &board, &db, local, &token, RetryPolicy::default()));
        std::thread::sleep(Duration::from_millis(30));
        cancel.cancel();
        handle.join().expect("the loop returned after the cancellation");

        drop(runtime);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
