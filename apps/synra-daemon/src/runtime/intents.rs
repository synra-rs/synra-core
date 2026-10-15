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

use synra_core::intent::types::Intent;
use synra_protocol::ids::IntentId;
use synra_store::records::IntentRecord;

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

        let record = {
            let board = self.board.lock();
            let Some(found) = board.get(id) else {
                return;
            };
            let record = record_of(found, store_now());
            // ★ Released here rather than at the end of the block. The board is the lock every intent command takes, so
            // holding it across the write below would make a database write block the next raise — and the write is the
            // slow half.
            drop(board);
            record
        };

        // Bound rather than written inline: the lock's guard has a `Drop`, and a temporary held across the `if let` body
        // is a lock held for longer than the write — which the lint is right to point at.
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
        let rows = match self.db.lock().load_intents() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("the stored intents could not be read: {error}");
                return 0;
            }
        };

        let mut board = self.board.lock();
        let mut restored = 0usize;
        for row in &rows {
            match serde_json::from_str::<Intent>(&row.document) {
                Ok(intent) => {
                    if board.restore(intent) {
                        restored += 1;
                    }
                    else {
                        // The board already holds this identifier. Not an error, but worth saying: it is also what a
                        // duplicate row would look like.
                        tracing::warn!(intent = row.intent_id, "an intent was restored twice");
                    }
                }
                Err(error) => {
                    tracing::error!(
                        intent = row.intent_id,
                        "a stored intent could not be read back and is being skipped: {error}"
                    );
                }
            }
        }
        restored
    }

    /// Forgets intents that finished long enough ago to be worth dropping.
    ///
    /// # Returns
    ///
    /// How many rows were removed.
    pub fn collect_intents(&self, keep_for_ms: i64) -> usize {
        collect(&self.db.lock(), keep_for_ms)
    }
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
/// Nothing is returned for a failure: a sweep that could not run is logged and the count is zero, because the caller is a
/// timer and has nothing to do with the answer. A command path that collected nothing would have to say so; a background
/// sweep that could not says it in the log.
pub(crate) fn collect(db: &synra_store::SynraDb, keep_for_ms: i64) -> usize {
    let before = store_now().saturating_sub(keep_for_ms);
    match db.forget_finished_intents(synra_core::intent::types::IntentState::final_kinds(), before) {
        Ok(removed) => removed,
        Err(error) => {
            tracing::error!("finished intents could not be collected: {error}");
            0
        }
    }
}

/// The row for one intent.
///
/// # Why `updated_ms` is "now" rather than a field of the intent
///
/// Because the intent does not carry one. `created_at_ms` is when it was raised and belongs to the kernel; when it last
/// changed is a fact about the row, and the retention sweep is the only thing that reads it. Taking it here — at the moment
/// of the write — is what makes it the time of the change rather than a value somebody had to remember to set.
///
/// # Why the document's failure is not returned
///
/// Because there is nothing a caller could do with it that is better than what the log says. An intent that will not
/// serialise is a bug in a type whose serialisation has its own tests, and the row is written with an empty document so
/// that the failure is visible on the next start as a document that cannot be read, beside the log line naming it.
#[must_use]
fn record_of(intent: &Intent, now_ms: i64) -> IntentRecord {
    IntentRecord {
        intent_id: intent.id.to_string(),
        // ★ The kernel's own name for the state, taken from `kind` rather than spelled here, so a renamed state cannot
        // leave the sweep comparing against a name nothing writes.
        state: intent.state.kind().to_owned(),
        created_ms: intent.created_at_ms,
        updated_ms: now_ms,
        origin_device: intent.origin.map(|device| device.to_string()),
        request_id: intent.request_id.map(|request| request.to_string()),
        document: match serde_json::to_string(intent) {
            Ok(document) => document,
            Err(error) => {
                tracing::error!(intent = %intent.id, "an intent could not be serialised: {error}");
                String::new()
            }
        },
    }
}
