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

#[cfg(test)]
mod tests {
    use synra_protocol::inbound::ShareItem;
    use synra_store::records::IntentRecord;
    use synra_store::SynraDb;

    use super::*;
    use crate::intent::types::{Choice, IntentSource};

    fn database() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("a database");
        db.migrate().expect("migrates");
        db
    }

    fn share() -> IntentSource {
        IntentSource::Share {
            item: ShareItem {
                from: synra_protocol::ids::DeviceId::new(),
                mime: "text/plain".to_owned(),
                text: Some("https://example.com".to_owned()),
                transfers: Vec::new(),
                context_id: None,
            },
            source_app: None,
        }
    }

    fn raised(board: &mut Board, now_ms: i64) -> IntentId {
        let (id, _, created) = board.raise(share(), Choice::Automatic, None, None, now_ms);
        assert!(created, "a fresh fixture raises a new intent");
        id
    }

    #[test]
    fn an_intent_survives_a_round_trip_through_the_store() {
        // ★ The claim the shell could not make before: a restart is not a forgetting. The board is a value, so the test can
        // build a second one over the same rows exactly as a second process would.
        let db = database();
        let mut before = Board::new();
        let id = raised(&mut before, 1_000);
        let row = record_of(&before, id, 1_050).expect("the board holds it");
        db.save_intent(&row).expect("written down");

        let mut after = Board::new();
        let report = restore(&mut after, &db).expect("read back");
        assert_eq!(report.restored, 1);
        assert_eq!(report.skipped(), 0);

        let found = after.get(id).expect("the same intent");
        assert_eq!(found.id, before.get(id).expect("still there").id);
        assert_eq!(found.created_at_ms, 1_000, "the raising time, not the writing time");
        assert_eq!(found.state.kind(), "matching", "and the state it was in");
    }

    #[test]
    fn an_identifier_the_board_does_not_hold_is_not_a_row() {
        // A sweep that dropped an intent while a checkpoint was in flight is a race, not an error: there is nothing to
        // write, and inventing an empty row would make the store hold an intent no board ever had.
        let board = Board::new();
        assert!(record_of(&board, IntentId::new(), 0).is_none());
    }

    #[test]
    fn a_row_whose_document_cannot_be_read_is_named_and_skipped() {
        // ★ A host that refused to start over this would turn one unreadable row into the loss of every intent behind it —
        // including the ones a peer is waiting on. The report is what makes the loss visible instead of silent.
        let db = database();
        db.save_intent(&IntentRecord {
            intent_id: IntentId::new().to_string(),
            state: "succeeded".to_owned(),
            created_ms: 0,
            updated_ms: 0,
            origin_device: None,
            request_id: None,
            document: "{\"not\":\"an intent\"}".to_owned(),
        })
        .expect("stored");

        let mut board = Board::new();
        let report = restore(&mut board, &db).expect("the rows are readable");
        assert_eq!(report.restored, 0);
        assert_eq!(report.unreadable.len(), 1, "the row is named, not counted");
        assert!(board.is_empty(), "nothing was put back");
    }

    #[test]
    fn a_second_restore_names_the_duplicate_rather_than_rolling_the_intent_back() {
        // The board already holding an identifier is not the same fact as a corrupt row, and overwriting would move the
        // intent's state backwards — which looks like progress to everything downstream.
        let db = database();
        let mut board = Board::new();
        let id = raised(&mut board, 1_000);
        db.save_intent(&record_of(&board, id, 1_000).expect("a row")).expect("stored");

        let first = restore(&mut board, &db).expect("readable");
        assert_eq!(first.restored, 0);
        assert_eq!(first.duplicates, vec![id.to_string()]);

        let mut empty = Board::new();
        assert_eq!(restore(&mut empty, &db).expect("readable").restored, 1);
    }

    #[test]
    fn only_finished_intents_past_the_window_are_collected() {
        // ★ The design's rule has two halves, and a sweep that dropped only one of them is the version that deletes work in
        // flight. `now = 10_000`, retention one second: finished at 8 000 goes, finished at 9 500 stays, and the intent that
        // is still matching is never a candidate no matter how old it is.
        let db = database();
        let mut board = Board::new();
        let old = raised(&mut board, 1_000);
        let recent = raised(&mut board, 1_000);
        let live = raised(&mut board, 1_000);
        board.cancel(old, "the user changed their mind").expect("finished");
        board.cancel(recent, "the user changed their mind").expect("finished");
        db.save_intent(&record_of(&board, old, 8_000).expect("a row")).expect("stored");
        db.save_intent(&record_of(&board, recent, 9_500).expect("a row")).expect("stored");
        db.save_intent(&record_of(&board, live, 1_000).expect("a row")).expect("stored");

        let removed = collect(&db, 1_000, 10_000).expect("collects");
        assert_eq!(removed, 1, "only the finished intent past the window");
        let left = db.load_intents().expect("readable");
        assert!(left.iter().any(|row| row.intent_id == live.to_string()), "work in flight stays");
        assert!(left.iter().any(|row| row.intent_id == recent.to_string()), "a recent result stays");
    }
}
