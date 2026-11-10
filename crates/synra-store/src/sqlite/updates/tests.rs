use super::{DbError, MAX_ATTEMPTS, PluginUpdateCheck, RETRY_BASE_MS, SynraDb};
use super::super::PluginVersionRecord;

fn check() -> PluginUpdateCheck {
    PluginUpdateCheck {
        plugin_id: "@acme/hello".to_owned(),
        current_version: "1.0.0".to_owned(),
        checked_at_ms: 123,
        registry: None,
        available_version: Some("2.0.0".to_owned()),
        added_capabilities: vec!["log:*".to_owned()],
        attempts: 0,
        retry_at_ms: None,
    }
}

fn database() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("database");
    db.migrate().expect("schema");
    db.insert_plugin("@acme/hello", false, false, "good", 1, 1)
        .expect("plugin");
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/hello",
        version: "1.0.0",
        artifact: "wasm",
        digest: "digest",
        manifest: "{}",
        installed_ms: 1,
        ..Default::default()
    })
    .expect("version");
    db
}

#[test]
fn a_failed_automatic_install_is_retried_sooner_than_a_day() {
    // ★ A transient failure used to wait for tomorrow. The first two failures back off half an hour and an hour; the
    // third gives up on the fast path and leaves the daily check.
    let db = database();
    assert!(db.save_plugin_update_check(&check()).expect("save"));

    assert!(db.note_update_failure(&check(), 1_000).expect("first"));
    // The retry itself re-checks and saves; the same available version must keep the attempted count.
    assert!(db.save_plugin_update_check(&check()).expect("re-save"));
    let after_retry = db
        .plugin_update_check("@acme/hello")
        .expect("read")
        .expect("a check");
    assert_eq!(
        after_retry.attempts, 1,
        "a re-check keeps the failure count"
    );
    assert_eq!(after_retry.retry_at_ms, Some(1_000 + RETRY_BASE_MS));
    assert!(db.note_update_failure(&check(), 2_000).expect("second"));
    assert_eq!(
        db.plugin_update_check("@acme/hello")
            .expect("read")
            .expect("check")
            .retry_at_ms,
        Some(2_000 + RETRY_BASE_MS * 2)
    );
    assert!(db.note_update_failure(&check(), 3_000).expect("third"));
    let saved = db
        .plugin_update_check("@acme/hello")
        .expect("read")
        .expect("a check");
    assert_eq!(saved.attempts, MAX_ATTEMPTS);
    assert_eq!(saved.retry_at_ms, None, "the daily check takes over");
    let mut next = check();
    next.available_version = Some("3.0.0".to_owned());
    next.checked_at_ms = 4_000;
    assert!(db.save_plugin_update_check(&next).expect("new version"));
    let reset = db
        .plugin_update_check("@acme/hello")
        .expect("read")
        .expect("a check");
    assert_eq!(
        reset.attempts, 0,
        "a different version starts its own count"
    );
    assert!(
        !db.note_update_failure(&check(), 5_000)
            .expect("old candidate")
    );
}

#[test]
fn a_late_failure_cannot_change_a_replacement_check() {
    let db = database();
    let first = check();
    assert!(db.save_plugin_update_check(&first).expect("save"));
    let mut replacement = first.clone();
    replacement.checked_at_ms += 1;
    assert!(
        db.save_plugin_update_check(&replacement)
            .expect("new check")
    );
    assert!(!db.note_update_failure(&first, 1_000).expect("late failure"));
    assert_eq!(
        db.plugin_update_check(&first.plugin_id).expect("read"),
        Some(replacement)
    );
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/hello",
        version: "1.1.0",
        artifact: "wasm",
        digest: "new",
        manifest: "{}",
        installed_ms: 2,
        ..Default::default()
    })
    .expect("replace installed version");
    assert!(!db.note_update_failure(&first, 1_000).expect("old version"));
}

#[test]
fn changing_the_source_resets_attempts_and_rejects_old_failures() {
    let db = database();
    let first = check();
    db.save_plugin_update_check(&first).expect("save");
    assert!(db.note_update_failure(&first, 1_000).expect("failure"));
    db.set_config(
        "plugins.registry",
        &serde_json::json!("https://new.example"),
        2,
    )
    .expect("source");
    assert!(!db.note_update_failure(&first, 2_000).expect("old source"));
    let mut next = first;
    next.registry = Some(serde_json::json!("https://new.example").to_string());
    assert!(
        db.save_plugin_update_check(&next)
            .expect("new source check")
    );
    assert_eq!(
        db.plugin_update_check(&next.plugin_id).expect("read"),
        Some(next)
    );
}

#[test]
fn retry_deadlines_saturate_and_attempt_counts_remain_bounded() {
    let db = database();
    let first = check();
    db.save_plugin_update_check(&first).expect("save");
    assert!(db.note_update_failure(&first, i64::MAX).expect("failure"));
    assert_eq!(
        db.plugin_update_check(&first.plugin_id)
            .expect("read")
            .expect("check")
            .retry_at_ms,
        Some(i64::MAX)
    );
    for _ in 0..10 {
        assert!(db.note_update_failure(&first, i64::MAX).expect("failure"));
    }
    let saved = db
        .plugin_update_check(&first.plugin_id)
        .expect("read")
        .expect("check");
    assert_eq!(saved.attempts, MAX_ATTEMPTS);
    assert_eq!(saved.retry_at_ms, None);
    let mut negative = first;
    negative.available_version = None;
    db.save_plugin_update_check(&negative).expect("no update");
    assert!(
        !db.note_update_failure(&negative, 1_000)
            .expect("no automatic attempt")
    );
}

#[test]
fn a_negative_check_replaces_an_update_and_keeps_its_time() {
    let db = database();
    let mut check = check();
    assert!(db.save_plugin_update_check(&check).expect("save"));
    assert_eq!(
        db.plugin_update_checks().expect("read"),
        vec![check.clone()]
    );
    check.available_version = None;
    check.added_capabilities.clear();
    check.checked_at_ms = 456;
    assert!(db.save_plugin_update_check(&check).expect("replace"));
    assert_eq!(db.plugin_update_checks().expect("read"), vec![check]);
}

#[test]
fn replacing_a_version_invalidates_its_check_and_refuses_a_late_answer() {
    let db = database();
    assert!(db.save_plugin_update_check(&check()).expect("save"));
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/hello",
        version: "2.0.0",
        artifact: "wasm",
        digest: "new digest",
        manifest: "{}",
        installed_ms: 2,
        ..Default::default()
    })
    .expect("replace");
    assert!(db.plugin_update_checks().expect("read").is_empty());
    assert!(!db.save_plugin_update_check(&check()).expect("late answer"));
}

#[test]
fn uninstalling_cascades_the_check_and_refuses_a_late_answer() {
    let mut db = database();
    assert!(db.save_plugin_update_check(&check()).expect("save"));
    assert!(db.remove_plugin("@acme/hello").expect("remove"));
    assert!(db.plugin_update_checks().expect("read").is_empty());
    assert!(!db.save_plugin_update_check(&check()).expect("late answer"));
    let remaining: i64 = db
        .connection
        .query_row("SELECT COUNT(*) FROM plugin_update_checks", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(remaining, 0);
}

#[test]
fn corrupt_capabilities_are_reported_instead_of_hidden() {
    let db = database();
    db.save_plugin_update_check(&check()).expect("save");
    db.connection
        .execute(
            "UPDATE plugin_update_checks SET added_capabilities = 'broken'",
            [],
        )
        .expect("corrupt");
    assert!(matches!(
        db.plugin_update_checks(),
        Err(DbError::NotJson { .. })
    ));
}

#[test]
fn switching_registries_invalidates_checks_and_refuses_a_late_answer() {
    let db = database();
    let mut check = check();
    assert!(db.save_plugin_update_check(&check).expect("save"));
    let registry = serde_json::json!("https://registry.example");
    db.set_config("plugins.registry", &registry, 1)
        .expect("registry");
    assert!(db.plugin_update_checks().expect("checks").is_empty());
    assert!(!db.save_plugin_update_check(&check).expect("late answer"));
    check.registry = Some(registry.to_string());
    assert!(
        db.save_plugin_update_check(&check)
            .expect("new registry's answer")
    );
    assert_eq!(
        db.plugin_update_check(&check.plugin_id).expect("check"),
        Some(check)
    );
}
