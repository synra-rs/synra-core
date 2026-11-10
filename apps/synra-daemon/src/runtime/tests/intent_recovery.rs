use super::*;

// ── Surviving a restart ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_intent_survives_a_restart() {
    // ★ The whole point of persisting, driven through the daemon rather than the library.
    //
    // Before this, the board was a `HashMap` in memory and nothing wrote it down: a daemon that restarted lost every intent
    // it was working on. The second runtime below is over the **same** database, which is what a restart is.
    let dir = TempDir::new("intent-restart");
    let (first, db) = runtime_shared(dir.path());

    let raised = first
        .intent_dispatch("text/plain", "https://example.test/a")
        .expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();
    assert_eq!(
        db.lock().intent_count().expect("counted"),
        1,
        "it was written down"
    );

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1, "and read back");
    assert!(
        second.intent_snapshot(&id).is_ok(),
        "the board remembers the intent"
    );
}

#[test]
fn a_restored_intent_is_the_same_intent_rather_than_a_new_one() {
    // ★ Why `restore` is not `raise`.
    //
    // `raise` mints an identifier and a trace. A restored intent has both, and a restart that gave it new ones would mean a
    // peer resending the request it originally raised is answered with a **second** intent — and the action runs twice,
    // which is the exact failure this path exists to prevent.
    let dir = TempDir::new("intent-same");
    let (first, db) = runtime_shared(dir.path());

    let raised = first
        .intent_dispatch("text/plain", "https://example.test/a")
        .expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();
    let trace_before = first.intent_snapshot(&id).expect("a snapshot")["trace"].clone();

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1);

    let snapshot = second.intent_snapshot(&id).expect("the same intent");
    assert_eq!(
        snapshot["intent"].as_str(),
        Some(id.as_str()),
        "the same identifier"
    );
    assert_eq!(snapshot["trace"], trace_before, "and the same trace");
}

#[test]
fn a_restart_does_not_bring_back_an_intent_twice() {
    // Restoring is idempotent from the caller's side: two runtimes reading one store, then restoring again, must leave one
    // intent on the board — a duplicate would be offered to the user twice.
    let dir = TempDir::new("intent-twice");
    let (first, db) = runtime_shared(dir.path());
    let raised = first
        .intent_dispatch("text/plain", "https://example.test/a")
        .expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1);
    assert_eq!(second.restore_intents(), 0, "nothing left to restore");
    assert_eq!(second.board.lock().len(), 1, "and still one intent");
    assert!(second.intent_snapshot(&id).is_ok());
}

#[test]
fn an_empty_store_restores_nothing_rather_than_failing() {
    // A first start, which is the ordinary case.
    let dir = TempDir::new("intent-empty");
    let runtime = runtime(dir.path());

    assert_eq!(runtime.restore_intents(), 0);
    assert_eq!(runtime.board.lock().len(), 0);
}

#[test]
fn a_document_that_cannot_be_read_is_skipped_rather_than_fatal() {
    // ★ The choice, made explicitly: a row written by a build whose shape has changed must not stop the daemon from
    // starting. The alternative is losing every intent — including the ones a peer is waiting on — because of one row.
    let dir = TempDir::new("intent-bad");
    let (first, db) = runtime_shared(dir.path());
    let raised = first
        .intent_dispatch("text/plain", "https://example.test/a")
        .expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();

    // A second intent whose document is not an intent at all, written behind the daemon's back.
    let good = db.lock().load_intents().expect("loaded").remove(0);
    db.lock()
        .save_intent(&IntentRecord {
            intent_id: "01a14199-f364-7612-af4f-000000000001".to_owned(),
            state: "matching".to_owned(),
            created_ms: 2_000,
            updated_ms: 2_000,
            origin_device: None,
            request_id: None,
            document: "not an intent".to_owned(),
        })
        .expect("written");

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1, "the readable one");
    assert!(
        second.intent_snapshot(&id).is_ok(),
        "and the daemon started anyway"
    );
    let _ = good;
}
