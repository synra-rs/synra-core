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

/// A dispatched intent, as a peer's request or a remote decision would leave one.
fn dispatching(board: &mut Board, now_ms: i64) -> IntentId {
    let (id, _, created) = board.raise(
        IntentSource::Direct {
            plugin_id: synra_protocol::ids::PluginId::parse("@acme/opener").expect("a plugin id"),
            action: "open".to_owned(),
            params: serde_json::json!({"url": "https://example.com"}),
            target: synra_protocol::ids::DeviceId::new(),
        },
        Choice::Automatic,
        None,
        None,
        now_ms,
    );
    assert!(created, "a direct source is raised rather than matched");
    id
}

#[test]
fn a_dispatch_nobody_answered_ends_after_the_late_answer_window() {
    // ★ The invariant: `Dispatching` is a state with an answer coming. Once the far side's late queue has expired
    // (`late_queue::MAX_AGE_MS`), no answer can arrive — and a row that stays in flight for ever is both a lie on the
    // home page and uncollectable, because the retention sweep only takes finished intents.
    let mut board = Board::new();
    let id = dispatching(&mut board, 1_000);
    assert!(board.get(id).expect("there").state.is_running());

    assert!(
        expire_unanswered(&mut board, 1_000 + crate::late_queue::MAX_AGE_MS - 1).is_empty(),
        "inside the window an answer may still arrive"
    );
    assert!(board.get(id).expect("there").state.is_running());

    let expired = expire_unanswered(&mut board, 1_000 + crate::late_queue::MAX_AGE_MS);
    assert_eq!(expired, vec![id]);
    assert!(
        matches!(board.get(id).expect("there").state, IntentState::TimedOut { .. }),
        "the dispatch ends as unanswered, not failed: the action may have run over there"
    );

    // ★ And it is not rolled back by a second sweep. Moving a final intent to `TimedOut` would erase an outcome the far
    // side did report, which is the one thing a late answer must never do.
    assert!(expire_unanswered(&mut board, i64::MAX).is_empty());
    assert!(matches!(board.get(id).expect("there").state, IntentState::TimedOut { .. }));
}

#[test]
fn an_intent_that_already_ended_is_never_turned_into_an_unanswered_one() {
    let mut board = Board::new();
    let id = dispatching(&mut board, 1_000);
    board
        .conclude(id, Ok(serde_json::json!("opened")), 5)
        .expect("ended");

    assert!(expire_unanswered(&mut board, i64::MAX).is_empty());
    assert!(matches!(board.get(id).expect("there").state, IntentState::Succeeded { .. }));
}
