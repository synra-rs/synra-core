//! Putting the board on disk, and reading it back.
//!
//! # Why this lives in the kernel rather than in a host
//!
//! Because **both** hosts keep a board and both need to survive a restart. The daemon wrote its own checkpoint and restore
//! first; the window had neither, so a desktop restart forgot every intent — including the remote action a peer was still
//! waiting on, which is the case that matters: the peer retries, the window has never heard of the request, and the action
//! runs a second time. A third copy of the row mapping would be a third place for the state names to drift from the ones
//! `Board` actually produces, so the mapping is here, beside the board it describes.
//!
//! # What the caller still owns
//!
//! The locks, and the decision about what a failure means. `record_of` takes a board by reference, so a host can take its
//! board guard, build the row, drop the guard, and only then take the database — the order the daemon already documents,
//! and the one a helper that took both locks inside would silently reverse. A write that fails is **logged, not refused**,
//! because it happens after the action has happened; that judgement is the host's, and this module only reports.
//!
//! # Why a row that will not deserialise is skipped rather than fatal
//!
//! Because the alternative is a host that will not start. A document written by an older build whose shape has changed is a
//! real possibility, and the choice is between losing that one intent and losing all of them. [`restore`] names every row
//! it could not read so the loss is visible rather than silent.

use synra_protocol::ids::IntentId;
use synra_store::records::IntentRecord;
use synra_store::{DbError, SynraDb};

use super::board::Board;
use super::types::{Intent, IntentState};

/// How long a finished intent is kept, matching `17 §6`.
///
/// ★ One constant for both hosts. It was written in the daemon's `serve.rs` and nowhere else, which was right while the
/// daemon was the only host with rows; a shell that restores and prunes needs the same number, and two constants with the
/// same value are two places to change it.
pub const INTENT_RETENTION_MS: i64 = 24 * 60 * 60 * 1_000;

/// What [`restore`] did.
///
/// ★ The two failure lists rather than a count: a host's log line is the only place a user can see which intent was lost,
/// and "three rows were skipped" is not something anyone can act on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
    /// Intents the board did not already hold.
    pub restored: usize,
    /// Rows whose identifier the board already held, named.
    ///
    /// A duplicate is what a `save` racing a restore looks like, not a corrupt store, so it is reported separately from
    /// `unreadable`: the intent is fine, there is just already one.
    pub duplicates: Vec<String>,
    /// Rows whose document could not be read, with the identifier and why.
    pub unreadable: Vec<(String, String)>,
}

impl Restored {
    /// How many rows were not put back, for a one-line report.
    #[must_use]
    pub const fn skipped(&self) -> usize {
        self.duplicates.len() + self.unreadable.len()
    }
}

/// The row for one intent the board holds, or `None` when it holds no such intent.
///
/// # Why the identifier is typed
///
/// Because the caller has already parsed it — both hosts receive it as text and must answer "that is not an identifier"
/// before looking — and a second parse here would be a second place that decides what a valid id looks like.
#[must_use]
pub fn record_of(board: &Board, intent: IntentId, now_ms: i64) -> Option<IntentRecord> {
    board.get(intent).map(|found| row_of(found, now_ms))
}

/// The row for one intent value.
///
/// # Why `updated_ms` is "now" rather than a field of the intent
///
/// Because the intent does not carry one. `created_at_ms` is when it was raised and belongs to the kernel; when it last
/// changed is a fact about the row, and the retention sweep is the only thing that reads it. Taking it here — at the moment
/// of the write — is what makes it the time of the change rather than a value somebody had to remember to set.
///
/// # Why serialisation failure does not refuse
///
/// Because there is nothing a caller could do with it that is better than what the host's log says. An intent that will not
/// serialise is a bug in a type whose serialisation has its own tests, and the row is written with an empty document so
/// that the failure is visible on the next start as a document that cannot be read, beside the log line naming it.
#[must_use]
pub fn row_of(intent: &Intent, now_ms: i64) -> IntentRecord {
    IntentRecord {
        intent_id: intent.id.to_string(),
        // ★ The kernel's own name for the state, taken from `kind` rather than spelled here, so a renamed state cannot
        // leave the sweep comparing against a name nothing writes.
        state: intent.state.kind().to_owned(),
        created_ms: intent.created_at_ms,
        updated_ms: now_ms,
        origin_device: intent.origin.map(|device| device.to_string()),
        request_id: intent.request_id.map(|request| request.to_string()),
        document: serde_json::to_string(intent).unwrap_or_default(),
    }
}

/// Puts back every intent the store holds, oldest first.
///
/// # Why the order matters
///
/// Because [`Board::restore`] appends to the board's order, and the retention sweep walks that order to drop the oldest
/// finished intents. `load_intents` answers oldest first for exactly this reason; restoring in another order would make a
/// sweep consider a restored intent the newest thing on the board.
///
/// # Errors
///
/// [`DbError`] when the rows cannot be read at all. A single row that cannot be **interpreted** is not an error: it is
/// named in the report.
pub fn restore(board: &mut Board, db: &SynraDb) -> Result<Restored, DbError> {
    let rows = db.load_intents()?;
    Ok(restore_rows(board, &rows))
}

/// [`restore`] over rows a caller has already read.
///
/// # Why this is separate
///
/// Because a host that holds its board behind a lock should not take the database lock while holding it: the board guard
/// is what every intent command waits on, and a slow read would make the next raise wait for the disk. A caller loads the
/// rows first, drops that guard, and only then takes the board — and this is the half that does not need a database.
#[must_use]
pub fn restore_rows(board: &mut Board, rows: &[IntentRecord]) -> Restored {
    let mut report = Restored::default();
    for row in rows {
        match serde_json::from_str::<Intent>(&row.document) {
            Ok(intent) => {
                if board.restore(intent) {
                    report.restored += 1;
                }
                else {
                    report.duplicates.push(row.intent_id.clone());
                }
            }
            Err(error) => report.unreadable.push((row.intent_id.clone(), error.to_string())),
        }
    }
    report
}

/// Forgets finished intents that finished longer ago than `keep_for_ms`.
///
/// # Why "finished" comes from the kernel
///
/// Because it is the kernel's judgement, and a store that guessed it from a string would be a second place the state machine
/// is written down. The list is read when the sweep runs, so a state renamed in [`IntentState`] cannot leave this comparing
/// against a name nothing writes.
///
/// # Errors
///
/// [`DbError`] when the delete is refused.
pub fn collect(db: &SynraDb, keep_for_ms: i64, now_ms: i64) -> Result<usize, DbError> {
    db.forget_finished_intents(IntentState::final_kinds(), now_ms.saturating_sub(keep_for_ms))
}

/// Ends dispatched work whose answer can no longer arrive, and names what it ended.
///
/// # Why this runs after a restore
///
/// Because a restored `Dispatching` intent is work this device sent and is still "waiting" for — but the process that was
/// waiting is gone. The answer can still arrive for as long as the far side keeps it in its late queue
/// ([`crate::late_queue::MAX_AGE_MS`]); after that it cannot, and an intent that stays `Dispatching` for ever is both a
/// lie on the home page and a row the retention sweep can never collect (the sweep only takes **finished** intents).
///
/// # Why the caller writes the rows
///
/// Because this touches the board and nothing else. A host that restored rows already knows how to persist a changed
/// intent; doing it here would put a database handle into a function whose whole test is a board.
#[must_use]
pub fn expire_unanswered(board: &mut Board, now_ms: i64) -> Vec<IntentId> {
    // ★ Collected before any state change: `Board::all` borrows the board, and `expire_dispatch` needs it mutably.
    let stale: Vec<(IntentId, i64)> = board
        .all()
        .into_iter()
        .filter_map(|intent| {
            if !intent.state.is_running() {
                return None;
            }
            let waited = now_ms.saturating_sub(intent.created_at_ms);
            // `>=` rather than `>`: at exactly the late queue's last moment there is no further moment for an answer to
            // arrive, and the boundary is the one a test can state without arithmetic.
            (waited >= crate::late_queue::MAX_AGE_MS).then_some((intent.id, waited))
        })
        .collect();

    let mut expired = Vec::new();
    for (id, waited) in stale {
        let after = std::time::Duration::from_millis(u64::try_from(waited).unwrap_or(u64::MAX));
        if board.expire_dispatch(id, after).is_some() {
            expired.push(id);
        }
    }
    expired
}

#[cfg(test)]
mod tests;
