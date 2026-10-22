//! Keeping the board across a restart.
//!
//! # Why this exists
//!
//! Because the board is a `HashMap` in memory and nothing wrote it down. A daemon that restarted lost every intent it was
//! working on — including the ones a peer had asked for and was still waiting on, which is the case that matters: the peer
//! retries, the kernel has never heard of the request, and the action runs a second time. The design gives intents a
//! retention rule ("24 hours after they finish", `17 §6`), and a rule about rows needs rows.
//!
//! # What is written, and when
//!
//! One row per intent, rewritten whenever the intent changes. The command paths that move an intent — raising one,
//! answering one, cancelling one — call [`Runtime::checkpoint_intent`] with the identifier the library returned, so what is
//! stored is whatever the board now holds rather than a second opinion about it.
//!
//! # Why a failure to write is logged rather than refused
//!
//! Because the action has already happened. A command that reported "no" after the plugin ran would be telling the user
//! that nothing occurred when something did, and the honest pair is to report the answer and say plainly, in the log, that
//! the record of it did not reach the disk. Rolling the intent back instead would be a kernel claiming an action it took
//! did not happen — worse than a restart that forgets.
//!
//! This is the one place in the daemon where a failure is not turned into a refusal, and the reason is that it happens
//! *after* the point of no return rather than before it.

use synra_protocol::ids::IntentId;

use super::Runtime;

/// The wall clock, as the store spells it.
///
/// The daemon reads a `u64` and every column in the store is an `i64`. The conversion saturates rather than wrapping: a
/// clock reading that does not fit in an `i64` is a machine whose clock is wrong by more than a century, and a wrapped
/// value would be a *negative* timestamp — which the retention sweep compares with `<`, so it would collect everything.
#[must_use]
fn store_now() -> i64 {
    i64::try_from(super::now_ms()).unwrap_or(i64::MAX)
}

impl Runtime {
    /// Writes one intent, as the board now holds it.
    ///
    /// Does nothing when the name is not an identifier or the board has no such intent — a caller that names one the sweep
    /// has already dropped is a race with the sweep, not an error.
    pub fn checkpoint_intent(&self, intent: &str) {
        let Ok(id) = intent.parse::<IntentId>() else {
            tracing::warn!(intent, "an intent id that cannot be parsed was not written down");
            return;
        };

        // ★ The board guard is released before the database is touched. The board is the lock every intent command takes,
        // and holding it across a write would make the next raise wait for the disk. The mapping itself lives in the kernel
        // (`synra_core::intent::persist`) because the window host writes the same rows.
        let record = {
            let board = self.board.lock();
            synra_core::intent::persist::record_of(&board, id, store_now())
        };
        let Some(record) = record else {
            return;
        };
        if record.document.is_empty() {
            tracing::error!(intent, "an intent could not be serialised, so its row carries no document");
        }

        let saved = self.db.lock().save_intent(&record);
        if let Err(error) = saved {
            tracing::error!(
                intent,
                "the intent could not be written down: {error}. The action it describes has already happened, so this is \
                 a record a restart will not have — not a command that failed."
            );
        }
    }

    /// Puts back every intent the store holds, oldest first.
    ///
    /// # Returns
    ///
    /// How many were restored, so the caller can say so rather than assume.
    ///
    /// # Why a row that will not deserialise is skipped rather than fatal
    ///
    /// Because the alternative is a daemon that will not start. A document written by an older build whose shape has since
    /// changed is a real possibility, and the choice is between losing that one intent and losing all of them — including
    /// the ones a peer is waiting on. Each failure is logged with the intent it names, so the loss is visible.
    pub fn restore_intents(&self) -> usize {
        // ★ The rows first, then the board. The reverse order is the one that would hold the board's lock across a disk
        // read, and this runs beside a running kernel more often than the word "start-up" suggests (a test builds a
        // `Runtime` and restores into it).
        let rows = match self.db.lock().load_intents() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("the stored intents could not be read: {error}");
                return 0;
            }
        };

        let mut board = self.board.lock();
        let report = synra_core::intent::persist::restore_rows(&mut board, &rows);
        // ★ Released before the log lines: the board is the lock every intent command takes, and a line about a row it
        // could not read is not a reason to hold it while `tracing` decides where to write.
        drop(board);
        for (intent, why) in &report.unreadable {
            tracing::error!("a stored intent could not be read back and is being skipped: {intent}: {why}");
        }
        for intent in &report.duplicates {
            // The board already holds this identifier. Not an error, but worth saying: it is also what a duplicate row
            // would look like.
            tracing::warn!(intent, "an intent was restored twice");
        }

        // ★ A restored `Dispatching` intent is work whose answer is still coming — but only inside the far side's late
        // queue. Once that window has passed, no answer can arrive; leaving it "running" would be wrong on every screen
        // and would make the row immortal, because the retention sweep only collects finished intents.
        let expired = {
            let mut board = self.board.lock();
            synra_core::intent::persist::expire_unanswered(&mut board, store_now())
        };
        for intent in &expired {
            self.checkpoint_intent(&intent.to_string());
        }
        if !expired.is_empty() {
            tracing::info!(count = expired.len(), "dispatched intents ended without an answer");
        }
        report.restored
    }

    /// Forgets intents that finished long enough ago to be worth dropping.
    ///
    /// # Returns
    ///
    /// How many rows were removed, and zero when they could not be.
    ///
    /// ★ This one still answers with a number, and that is a deliberate difference from [`sweep`]: it is a test-facing
    /// convenience, and a test that wants to know whether the collection *failed* calls `sweep` and reads
    /// [`GcReport::failures`]. Losing the failure here would matter if a command path used it; nothing does.
    pub fn collect_intents(&self, keep_for_ms: i64) -> usize {
        collect(&self.db.lock(), keep_for_ms).unwrap_or_else(|error| {
            tracing::error!("finished intents could not be collected: {error}");
            0
        })
    }
}

/// How many devices merely *heard from* are kept.
///
/// The design's storage table gives this row a ceiling ("keep the most recent 500", `17 §6`). It is the one GC target in
/// that section which genuinely fills up: the table is written by the discovery thread, and a kernel on a shared network —
/// an office, a café, a train — hears a new device every few minutes for as long as it runs.
pub(crate) const SEEN_DEVICE_CEILING: usize = 500;

/// The whole sweep: finished intents past their retention, and devices heard from beyond the ceiling.
///
/// # Returns
///
/// A [`GcReport`]: what was removed, and what could not be.
///
/// # Why both are here rather than two schedules
///
/// Because they are the same decision — "what is no longer worth keeping" — and two timers would be two places to change
/// when that decision changes. The database is the only thing either needs, which is what lets this run on a thread that
/// cannot hold the runtime.
#[must_use]
pub(crate) fn sweep(db: &synra_store::SynraDb, retention: Retention) -> GcReport {
    let mut failures = Vec::new();
    let intents = match collect(db, retention.intents_ms) {
        Ok(removed) => removed,
        Err(error) => {
            failures.push(error);
            0
        }
    };
    let devices = match db.forget_seen_devices_beyond(SEEN_DEVICE_CEILING) {
        Ok(removed) => removed,
        Err(error) => {
            failures.push(format!("devices heard from: {error}"));
            0
        }
    };
    // ★ The third target, and the one that only became collectable when it got a writer: `plugin_audit` is filled by the
    // sink `build_set` installs, and the design gives it seven days. A sweep written before that would have been collecting
    // an empty table.
    let audit = match db.forget_audit_before(store_now().saturating_sub(retention.audit_ms)) {
        Ok(removed) => removed,
        Err(error) => {
            failures.push(format!("recorded calls: {error}"));
            0
        }
    };
    GcReport { intents, devices, audit, failures }
}

/// How long each kind of record is kept.
///
/// A value rather than constants read inside the sweep, so a test can say "a day" without waiting one — the same reason the
/// schedule is a parameter in `serve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Retention {
    /// How long a finished intent is kept.
    pub(crate) intents_ms: i64,
    /// How long a recorded call is kept.
    pub(crate) audit_ms: i64,
}

/// What one sweep did, and what it could not do.
///
/// ★ Why `failures` is a field rather than a log line.
///
/// The three collection targets used to swallow their errors: a delete that failed logged `tracing::error!` and returned
/// **zero**, so a sweep that could not do its job was byte-for-byte the same answer as a sweep with nothing to do — and the
/// caller printed nothing at all, because every count was zero. A background thread's log line is also the easiest thing in
/// a system to miss, which is how a database that cannot be collected from stays broken for a week.
///
/// The caller is a timer, and the comment that said *"it has nothing to do with the answer"* was the reason this was written
/// that way. That is no longer true: this loop can report, and a test can assert on what it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GcReport {
    /// Finished intents past their retention.
    pub(crate) intents: usize,
    /// Devices heard from beyond the ceiling.
    pub(crate) devices: usize,
    /// Recorded calls past their retention.
    pub(crate) audit: usize,
    /// One line per target that could not be collected, named so a reader knows which.
    pub(crate) failures: Vec<String>,
}

impl GcReport {
    /// How many rows were removed altogether.
    #[must_use]
    pub(crate) const fn removed(&self) -> usize {
        self.intents + self.devices + self.audit
    }
}

/// The schedule the design calls `GcTask`: what to collect, and how often.
///
/// ★ Why the schedule is a value rather than three constants.
///
/// Because the constants lived at the top of `serve.rs` and the sweep's own tests had to restate them; a task carrying its
/// own interval and retention is what lets a test run the real loop with milliseconds, and what makes "the schedule" a thing
/// a reader can point at rather than a rule assembled from three separate `const`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GcTask {
    /// How long each kind of record is kept.
    pub(crate) retention: Retention,
    /// How long to wait after start-up before the first sweep.
    pub(crate) first_delay: std::time::Duration,
    /// How often to sweep after that.
    pub(crate) every: std::time::Duration,
}

/// The retention sweep, over a database rather than a runtime.
///
/// # ★ Why this is a free function and not only a method
///
/// Because the thing that runs it on a schedule is a **thread** that cannot hold the `Runtime`: the daemon owns the runtime
/// on the stack of its accept loop, and the sweep must not block there. The thread is given the database handle instead —
/// which is the only part of the runtime the sweep touches — so the schedule and the command path necessarily use the same
/// implementation rather than two that agree today.
///
/// # Why the finished states come from the kernel
///
/// Because "finished" is the kernel's judgement. The list is read at the moment of the sweep, so a state renamed in the
/// kernel cannot leave this comparing against a name nothing writes.
///
/// # Errors
///
/// A failure comes back as a sentence naming the target, and [`sweep`] puts it in the report. It used to be logged and
/// turned into zero, which made "could not collect" and "nothing to collect" the same answer — see [`GcReport`].
pub(crate) fn collect(db: &synra_store::SynraDb, keep_for_ms: i64) -> Result<usize, String> {
    synra_core::intent::persist::collect(db, keep_for_ms, store_now()).map_err(|error| format!("finished intents: {error}"))
}

