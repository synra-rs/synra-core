//! Scheduled cleanup of finished work and bounded discovery history.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use super::sleep_until_shutdown;

/// How long a finished intent is kept, in milliseconds.
///
/// Twenty-four hours, from the design's storage table (`17 §6`: "finished, then cleaned after 24 hours"). Long enough that
/// a user can still read what happened yesterday, short enough that a device raising intents for months does not carry all
/// of them.
const INTENT_RETENTION_MS: i64 = 24 * 60 * 60 * 1_000;

/// How often the retention sweep runs.
///
/// An hour, as the design's `GcTask` says.
const GC_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How long a recorded call is kept, in milliseconds.
///
/// Seven days, from the design's storage table (`17 §6`). Longer than a log's window because the record carries no content:
/// a capability names a destination, never what was sent to it, which is the whole reason this is safe to keep.
const AUDIT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// How long the first sweep waits after start-up.
///
/// ★ Not zero, and the reason is the design's own requirement that GC runs when the daemon is *idle*.
///
/// A daemon that has just started is migrating the database, reading plugin manifests and claiming the directory — and a
/// retention sweep beside them would be IO nobody asked for at the one moment the kernel is already busy. A minute is long
/// enough for start-up to finish and short enough that a daemon restarted often still collects.
const GC_FIRST_DELAY: Duration = Duration::from_secs(60);

/// The schedule this daemon collects on: the design's `GcTask`, as a value.
pub(super) const fn gc_task() -> crate::runtime::intents::GcTask {
    crate::runtime::intents::GcTask {
        retention: crate::runtime::intents::Retention {
            intents_ms: INTENT_RETENTION_MS,
            audit_ms: AUDIT_RETENTION_MS,
        },
        first_delay: GC_FIRST_DELAY,
        every: GC_INTERVAL,
    }
}

/// The same schedule at a speed a test can wait for, which is the reason the schedule is a value.
#[cfg(test)]
pub(super) const fn fast_gc_task() -> crate::runtime::intents::GcTask {
    crate::runtime::intents::GcTask {
        retention: crate::runtime::intents::Retention {
            intents_ms: INTENT_RETENTION_MS,
            audit_ms: AUDIT_RETENTION_MS,
        },
        first_delay: Duration::from_millis(1),
        every: Duration::from_millis(5),
    }
}

/// Runs the retention sweep on a schedule, for as long as the daemon serves.
///
/// # Why this is a thread of its own
///
/// For the reason the heartbeat is: the accept loop blocks on a client, so a sweep done from there would happen only when
/// somebody connected — and a daemon nobody talks to would never collect anything. It also must not hold the `Runtime`,
/// which the accept loop owns on its stack, so it is given the database handle and the two durations it needs.
///
/// # Why the durations are parameters and the constants are the caller's
///
/// Because a test that waited an hour to see whether the sweep ran would not be a test. The schedule is decided where the
/// daemon is built and passed in, so the same loop can be driven with milliseconds.
pub(super) fn collect_loop(
    db: &Arc<Mutex<synra_store::SynraDb>>,
    supervisor: &Arc<synra_core::supervisor::Supervisor>,
    task: crate::runtime::intents::GcTask,
) {
    let first_delay = task.first_delay;
    let every = task.every;
    // ★ The first wait is interruptible in slices, so a daemon asked to stop during its first minute does not take the
    // whole minute to notice. The heartbeat loop has the same shape for the same reason.
    if !sleep_until_shutdown(supervisor, first_delay) {
        return;
    }

    while !supervisor.is_shutting_down() {
        let collected = crate::runtime::intents::sweep(&db.lock(), task.retention);
        // ★ A sweep that could not finish says so, on the error stream and by name.
        //
        // It used to say nothing at all: every count was zero, and the failure was a log line written inside the store. A
        // database that cannot be collected from is the one thing about a sweep worth interrupting somebody for, and it was
        // the one thing this loop was silent about.
        for failure in &collected.failures {
            eprintln!("the retention sweep could not finish: {failure}");
        }
        if collected.intents > 0 {
            println!("collected {} finished intent(s)", collected.intents);
        }
        if collected.devices > 0 {
            println!("forgot {} device(s) heard from long ago", collected.devices);
        }
        if collected.audit > 0 {
            println!("forgot {} recorded call(s)", collected.audit);
        }
        // ★ One line for the sweep as a whole, and the reason `removed` is a method rather than a test helper: an
        // operator reading the log wants to know whether collection is happening at all, and three separate numbers that are
        // all zero look the same as a sweep that never ran.
        let removed = collected.removed();
        if removed > 0 {
            println!("the retention sweep removed {removed} row(s)");
        }
        if !sleep_until_shutdown(supervisor, every) {
            return;
        }
    }
}
