//! The durable audit trail, against a database that actually answers.

use crate::records::AuditRecord;
use crate::sqlite::SynraDb;

/// An open database with the migrations applied.
fn db() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    db
}

fn call(plugin: &str, capability: &str, outcome: &str, at_ms: i64) -> AuditRecord {
    AuditRecord {
        plugin_id: plugin.to_owned(),
        capability: capability.to_owned(),
        outcome: outcome.to_owned(),
        at_ms,
        elapsed_ms: Some(3),
        trace_id: None,
    }
}

#[test]
fn a_gated_call_survives_a_round_trip() {
    // ★ The point: `plugin_audit` was created by the first migration, its own comment says it is the durable half of the
    // trail, and nothing wrote it — so the audit a user sees was the last ten thousand calls of *this process*.
    let db = db();
    let written = call("@acme/notes", "device:list", "allowed", 1_000);
    db.record_audit(&written).expect("recorded");

    assert_eq!(db.audit_trail().expect("listed"), vec![written]);
}

#[test]
fn a_trace_survives_the_round_trip() {
    // ★ The DTO has carried `trace_id` from the first version and the row had no column to put it in, so "which action was
    // this?" had no answer after a restart. The column is nullable because rows written by an older build have no trace to
    // recover; a row that has one must come back with it.
    let db = db();
    let trace = "01a150c8-c332-768d-9dd1-981502aa1854";
    db.record_audit(&call("@acme/notes", "device:list", "allowed", 1_000)).expect("recorded");
    let mut traced = call("@acme/notes", "device:list", "allowed", 1_001);
    traced.trace_id = Some(trace.to_owned());
    db.record_audit(&traced).expect("recorded");

    let trail = db.audit_trail().expect("listed");
    assert_eq!(trail[0].trace_id.as_deref(), Some(trace), "the trace came back");
    assert_eq!(trail[1].trace_id, None, "and a row without one stays without");
}

#[test]
fn a_write_reports_its_duration_and_its_kind() {
    // ★ The hook the hosts install: every write method reports once, labelled with the operation's own name. A metric
    // that counted some writes and not others would be read as "the database is fast" while the slow write — the one the
    // user is waiting on — was not in the sample at all.
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let mut db = db();
    let seen: Arc<Mutex<Vec<(&'static str, Duration)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    db.observe_writes(Arc::new(move |kind, elapsed| sink.lock().expect("a lock").push((kind, elapsed))));

    db.record_audit(&call("@acme/notes", "device:list", "allowed", 1_000)).expect("recorded");
    db.set_config("test.key", &serde_json::json!(1), 10).expect("written");
    db.record_seen_device(&crate::records::Seen {
        device_id: "00000000-0000-4000-8000-0000000000aa".to_owned(),
        display_name: "Phone".to_owned(),
        platform: "android".to_owned(),
        seen_at_ms: 10,
        source: "udp".to_owned(),
    })
    .expect("seen");

    let seen = std::mem::take(&mut *seen.lock().expect("a lock"));
    let kinds: Vec<&str> = seen.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, vec!["audit", "config", "device"]);
    assert!(
        seen.iter().all(|(_, elapsed)| *elapsed < Duration::from_secs(1)),
        "a write against an in-memory database took a second: {seen:?}"
    );
}

#[test]
fn every_call_is_its_own_row() {
    // ★ Why this appends rather than upserts. Two `device:list` calls a millisecond apart are two facts, and "recent
    // activity" is a list of them — an upsert would collapse the history into a count of one.
    let db = db();
    db.record_audit(&call("@acme/notes", "device:list", "allowed", 1_000)).expect("recorded");
    db.record_audit(&call("@acme/notes", "device:list", "allowed", 1_001)).expect("recorded");
    db.record_audit(&call("@acme/notes", "device:list", "denied", 1_002)).expect("recorded");

    assert_eq!(db.audit_count().expect("counted"), 3);
}

#[test]
fn the_trail_comes_back_newest_first() {
    // A reader wants the most recent without sorting, and two calls in the same millisecond still have an order — the row
    // that was written second is the later one.
    let db = db();
    for (index, at) in [3_000, 1_000, 2_000].iter().enumerate() {
        db.record_audit(&call("@acme/notes", "log:info", "allowed", *at)).expect("recorded");
        let _ = index;
    }

    let ats: Vec<i64> = db.audit_trail().expect("listed").into_iter().map(|row| row.at_ms).collect();
    assert_eq!(ats, vec![3_000, 2_000, 1_000]);
}

#[test]
fn a_refusal_is_recorded_like_anything_else() {
    // The design's own reason for keeping this longer than a log: *"A refused one is the moment the capability system did
    // its job."* A trail that recorded only what succeeded would be one nobody could audit.
    let db = db();
    db.record_audit(&call("@acme/notes", "fs:read:/etc/shadow", "denied", 1_000)).expect("recorded");

    let trail = db.audit_trail().expect("listed");
    assert_eq!(trail[0].outcome, "denied");
    assert_eq!(trail[0].capability, "fs:read:/etc/shadow");
}

#[test]
fn a_call_that_did_not_run_has_no_elapsed_time() {
    // The one nullable column: a call refused by the gate never ran, so there is no duration to record — and a zero would
    // be a duration that says it was instant.
    let db = db();
    let mut refused = call("@acme/notes", "device:list", "denied", 1_000);
    refused.elapsed_ms = None;
    db.record_audit(&refused).expect("recorded");

    assert_eq!(db.audit_trail().expect("listed")[0].elapsed_ms, None);
}

#[test]
fn the_trail_is_kept_for_a_number_of_days_and_then_forgotten() {
    // ★ The design's retention: seven days. Unlike the intents' rule there is no state to protect — a record is written
    // once, when the call it is about has already ended — so age is the whole rule.
    //
    // The two records are ten days old and two days old, on either side of the window, rather than sitting exactly on the
    // boundary: a test whose answer depends on whether the comparison is `<` or `<=` is a test of the operator, and the
    // operator is not what this is about.
    let db = db();
    let day = 24 * 60 * 60 * 1_000;
    let now = 30 * day;
    db.record_audit(&call("@acme/notes", "device:list", "allowed", now - 10 * day)).expect("recorded");
    db.record_audit(&call("@acme/notes", "device:list", "allowed", now - 2 * day)).expect("recorded");

    let removed = db.forget_audit_before(now - 7 * day).expect("collected");

    assert_eq!(removed, 1, "the one outside the window, and only that");
    assert_eq!(db.audit_count().expect("counted"), 1);
    assert_eq!(db.audit_trail().expect("listed")[0].at_ms, now - 2 * day, "the recent one stayed");
}

#[test]
fn forgetting_does_not_touch_what_a_plugin_stored() {
    // The design's first requirement for GC, asserted here too: user data is never deleted.
    let db = db();
    db.insert_plugin("@acme/notes", true, true, "healthy", 1, 1).expect("a plugin row");
    db.storage_set("@acme/notes", "draft", "the user's words", 1_000).expect("stored");
    db.record_audit(&call("@acme/notes", "storage:local:write", "allowed", 0)).expect("recorded");

    assert_eq!(db.forget_audit_before(1_000).expect("collected"), 1);

    assert_eq!(
        db.storage_get("@acme/notes", "draft").expect("read").as_deref(),
        Some("the user's words"),
        "the plugin's data outlives the record of the call that wrote it"
    );
}

#[test]
fn an_empty_trail_says_so_rather_than_failing() {
    let db = db();

    assert_eq!(db.audit_trail().expect("listed"), Vec::new());
    assert_eq!(db.audit_count().expect("counted"), 0);
    assert_eq!(db.forget_audit_before(i64::MAX).expect("collected"), 0);
}

#[test]
fn a_call_before_the_epoch_is_still_a_call() {
    // A clock set wrong is a real installation, and a negative timestamp must not be mistaken for "no time recorded" —
    // which would make the record immortal, because `at_ms < cutoff` is false for a null-like value.
    let db = db();
    db.record_audit(&call("@acme/notes", "device:list", "allowed", -5_000)).expect("recorded");

    assert_eq!(db.audit_count().expect("counted"), 1);
    assert_eq!(db.forget_audit_before(0).expect("collected"), 1, "it is older than the epoch");
}

#[test]
fn one_plugins_trail_is_read_newest_first_and_within_the_limit() {
    // ★ The read the audit panel makes. Three claims at once, because a query that gets one of them wrong is still a
    // query that returns plausible rows: only this plugin's calls, the newest ones first, at most `limit` of them.
    let db = db();
    for at in [1_000, 2_000, 3_000] {
        db.record_audit(&call("@acme/notes", "device:list", "allowed", at)).expect("recorded");
    }
    db.record_audit(&call("@acme/chat", "log:info", "allowed", 4_000)).expect("recorded");

    let ats: Vec<i64> = db
        .audit_trail_for("@acme/notes", 0, 2)
        .expect("listed")
        .into_iter()
        .map(|row| row.at_ms)
        .collect();

    assert_eq!(ats, vec![3_000, 2_000], "newest first, another plugin excluded, the limit honoured");
}

#[test]
fn an_offset_walks_the_same_order_without_repeating_a_row() {
    // ★ "Show more" is an offset, not a second query with a different `limit`: a page the user has already seen must not
    // appear again, and the row order it walks is the same newest-first order the first page used.
    let db = db();
    for at in [1_000, 2_000, 3_000, 4_000] {
        db.record_audit(&call("@acme/notes", "device:list", "allowed", at)).expect("recorded");
    }

    let page = |offset: u32| -> Vec<i64> {
        db.audit_trail_for("@acme/notes", offset, 2)
            .expect("listed")
            .into_iter()
            .map(|row| row.at_ms)
            .collect()
    };

    assert_eq!(page(0), vec![4_000, 3_000]);
    assert_eq!(page(2), vec![2_000, 1_000]);
    assert!(page(4).is_empty(), "past the end is empty, not a repeat of the last page");
}

#[test]
fn a_limit_of_zero_answers_nothing_rather_than_everything() {
    // `LIMIT 0` is the SQL that says "nothing". A reader that treated zero as "no limit" would turn a malformed request
    // into the whole history.
    let db = db();
    db.record_audit(&call("@acme/notes", "device:list", "allowed", 1_000)).expect("recorded");

    assert!(db.audit_trail_for("@acme/notes", 0, 0).expect("listed").is_empty());
}

#[test]
fn forgetting_one_plugins_rows_leaves_the_other() {
    // The same rule as the ring: a button on one plugin's card must not clear another plugin's history.
    let db = db();
    db.record_audit(&call("@acme/notes", "device:list", "allowed", 1_000)).expect("recorded");
    db.record_audit(&call("@acme/chat", "log:info", "allowed", 2_000)).expect("recorded");

    assert_eq!(db.forget_audit_for("@acme/notes").expect("collected"), 1);

    assert!(db.audit_trail_for("@acme/notes", 0, 10).expect("listed").is_empty());
    assert_eq!(db.audit_trail_for("@acme/chat", 0, 10).expect("listed").len(), 1);
}
