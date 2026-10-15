//! Persisting intents, against a database that actually answers.

use crate::records::IntentRecord;
use crate::sqlite::SynraDb;

/// An open database with the migrations applied.
fn db() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    db
}

fn intent(id: &str, state: &str, at_ms: i64) -> IntentRecord {
    IntentRecord {
        intent_id: id.to_owned(),
        origin: "device-a".to_owned(),
        plugin_id: "@acme/notes".to_owned(),
        action: "create".to_owned(),
        args: "{\"title\":\"x\"}".to_owned(),
        state: state.to_owned(),
        created_ms: at_ms,
        updated_ms: at_ms,
        expires_ms: None,
    }
}

#[test]
fn an_intent_survives_a_round_trip() {
    // ★ The whole point: before this, an intent lived only in the kernel's `Board`, so a daemon restart lost every one of
    // them and the `intents` table was never written by anything.
    let db = db();
    let written = intent("i-1", "raised", 1_000);
    db.save_intent(&written).expect("saved");

    let loaded = db.load_intents().expect("loaded");

    assert_eq!(loaded, vec![written]);
}

#[test]
fn a_second_write_updates_rather_than_adding_a_row() {
    // An intent changes as it is worked on, and every change is the same intent. A store that inserted per change would
    // answer `load_intents` with a history — which is what the audit is for, not what a board is.
    let db = db();
    db.save_intent(&intent("i-1", "raised", 1_000)).expect("saved");
    db.save_intent(&intent("i-1", "succeeded", 2_000)).expect("saved again");

    let loaded = db.load_intents().expect("loaded");

    assert_eq!(loaded.len(), 1, "one intent, not two");
    assert_eq!(loaded[0].state, "succeeded");
    assert_eq!(loaded[0].updated_ms, 2_000);
}

#[test]
fn a_later_write_does_not_move_when_the_intent_was_raised() {
    // ★ `created_ms` is when the intent was raised, and a later write is not a later raising. Overwriting it would make
    // every intent look as though it had just started — and the retention rule below is measured from when it *finished*,
    // so the two must not be the same number by accident.
    let db = db();
    db.save_intent(&intent("i-1", "raised", 1_000)).expect("saved");
    db.save_intent(&intent("i-1", "succeeded", 9_000)).expect("saved again");

    let loaded = db.load_intents().expect("loaded");

    assert_eq!(loaded[0].created_ms, 1_000, "still raised at 1_000");
    assert_eq!(loaded[0].updated_ms, 9_000, "and last changed at 9_000");
}

#[test]
fn an_intent_with_no_deadline_keeps_none() {
    // The one nullable column: an intent nobody gave a deadline to has none, rather than a zero that means "the epoch".
    let db = db();
    let mut written = intent("i-1", "raised", 1_000);
    written.expires_ms = None;
    db.save_intent(&written).expect("saved");

    assert_eq!(db.load_intents().expect("loaded")[0].expires_ms, None);

    written.expires_ms = Some(5_000);
    db.save_intent(&written).expect("saved again");
    assert_eq!(db.load_intents().expect("loaded")[0].expires_ms, Some(5_000));
}

#[test]
fn intents_come_back_oldest_first() {
    // Two runs have to agree, or a board restored from the store would be in a different order each time.
    let db = db();
    for (id, at) in [("i-3", 3_000), ("i-1", 1_000), ("i-2", 2_000)] {
        db.save_intent(&intent(id, "raised", at)).expect("saved");
    }

    let loaded = db.load_intents().expect("loaded");

    assert_eq!(
        loaded.iter().map(|row| row.intent_id.as_str()).collect::<Vec<_>>(),
        vec!["i-1", "i-2", "i-3"]
    );
}

#[test]
fn only_finished_intents_that_are_old_enough_are_forgotten() {
    // ★ Both halves of the rule. Age alone would remove work in flight — an intent that has been running a long time is not
    // old data, and losing it silently is losing something a user asked for. State alone would remove an intent the moment
    // it finished, which is too soon to read it.
    let db = db();
    db.save_intent(&intent("done-old", "succeeded", 1_000)).expect("saved");
    db.save_intent(&intent("done-new", "succeeded", 9_000)).expect("saved");
    db.save_intent(&intent("running-old", "running", 1_000)).expect("saved");
    db.save_intent(&intent("failed-old", "failed", 1_000)).expect("saved");

    let removed = db
        .forget_finished_intents(&["succeeded", "failed", "cancelled"], 5_000)
        .expect("collected");

    assert_eq!(removed, 2, "the old finished ones, and only those");
    let left: Vec<String> = db.load_intents().expect("loaded").into_iter().map(|row| row.intent_id).collect();
    // ★ Ordered by when each was **raised**, not by what happened to it: `running-old` was raised at 1_000 and `done-new`
    // at 9_000, so the surviving row that has been waiting longest comes first. The first version of this assertion had
    // them the other way round, which would have been a store that reordered a board by state.
    assert_eq!(left, vec!["running-old".to_owned(), "done-new".to_owned()]);
}

#[test]
fn a_state_the_caller_did_not_name_is_never_collected() {
    // The finished states are the kernel's vocabulary and arrive as an argument. A state nobody called finished is work in
    // progress as far as this store is concerned, whatever it is spelled.
    let db = db();
    db.save_intent(&intent("i-1", "archived", 1_000)).expect("saved");

    assert_eq!(db.forget_finished_intents(&["succeeded"], 9_999).expect("collected"), 0);
    assert_eq!(db.intent_count().expect("counted"), 1);
}

#[test]
fn naming_no_finished_state_collects_nothing() {
    // ★ An empty `IN ()` is a syntax error in SQLite, so this is a branch rather than a query. It is a real case: a caller
    // that has not decided what "finished" means yet must not be handed a database fault for it.
    let db = db();
    db.save_intent(&intent("i-1", "succeeded", 1_000)).expect("saved");

    assert_eq!(db.forget_finished_intents(&[], 9_999).expect("collected"), 0);
    assert_eq!(db.intent_count().expect("counted"), 1, "and nothing was lost");
}

#[test]
fn the_state_is_bound_rather_than_assembled_into_the_query() {
    // A state name is text a caller supplies. This asserts the query is built from placeholders: a value containing SQL
    // either matches a row literally or matches nothing, and it never runs.
    let db = db();
    db.save_intent(&intent("i-1", "succeeded", 1_000)).expect("saved");
    db.save_intent(&intent("i-2", "succeeded'; DROP TABLE intents; --", 1_000)).expect("saved");

    let removed = db
        .forget_finished_intents(&["succeeded'; DROP TABLE intents; --"], 9_999)
        .expect("collected");

    assert_eq!(removed, 1, "the row with that literal state");
    // And the table is still there — which is the assertion that matters.
    assert_eq!(db.intent_count().expect("counted"), 1);
}

#[test]
fn an_empty_database_says_so_rather_than_failing() {
    let db = db();

    assert_eq!(db.load_intents().expect("loaded"), Vec::new());
    assert_eq!(db.intent_count().expect("counted"), 0);
    assert_eq!(db.forget_finished_intents(&["succeeded"], 9_999).expect("collected"), 0);
}

#[test]
fn collecting_intents_does_not_touch_what_a_plugin_stored() {
    // ★ The first of the two things `17 §6` says a collector must never delete: user data. `plugin_storage` is where a
    // plugin's own values live, and a GC that reached it would destroy work the user cannot get back.
    let db = db();
    db.insert_plugin("@acme/notes", true, true, "healthy", 1, 1).expect("a plugin row");
    db.storage_set("@acme/notes", "draft", "the user's own words", 1_000).expect("stored");
    db.save_intent(&intent("i-1", "succeeded", 1_000)).expect("saved");

    db.forget_finished_intents(&["succeeded"], 9_999).expect("collected");

    assert_eq!(
        db.storage_get("@acme/notes", "draft").expect("read").as_deref(),
        Some("the user's own words"),
        "the plugin's data outlives the intent that produced it"
    );
}
