use super::SynraDb;

fn database() -> SynraDb {
    let mut db = SynraDb::open_in_memory().unwrap();
    db.migrate().unwrap();
    db.insert_plugin("@a/ui", true, true, "installed", 1, 1)
        .unwrap();
    db.insert_plugin("@b/ui", true, true, "installed", 1, 1)
        .unwrap();
    db
}

fn revision(db: &SynraDb) -> i64 {
    db.plugin_authority("@a/ui").unwrap().unwrap().revision
}

#[test]
fn authority_changes_are_isolated_and_do_not_follow_health_or_wall_clock() {
    let db = database();
    let before = revision(&db);
    db.set_plugin_enabled("@b/ui", false, 1).unwrap();
    db.connection
        .execute(
            "UPDATE plugins SET health = 'faulted' WHERE plugin_id = '@a/ui'",
            [],
        )
        .unwrap();
    assert_eq!(revision(&db), before);
    db.set_plugin_enabled("@a/ui", false, 1).unwrap();
    let disabled = revision(&db);
    assert!(disabled > before);
    assert!(!db.plugin_authority("@a/ui").unwrap().unwrap().permits_ui());
    db.set_plugin_enabled("@a/ui", true, 1).unwrap();
    assert!(revision(&db) > disabled);
    db.record_grants("@a/ui", &[("log:info".to_owned(), true)], 1, "digest")
        .unwrap();
    let granted = revision(&db);
    db.record_grants("@a/ui", &[("log:info".to_owned(), false)], 1, "digest")
        .unwrap();
    assert!(revision(&db) > granted);
    let revoked = revision(&db);
    db.set_plugin_trusted("@a/ui", false, 1).unwrap();
    assert!(revision(&db) > revoked);
}

#[test]
fn inactive_candidates_do_not_revoke_pages_but_current_version_changes_do() {
    let db = database();
    let before = revision(&db);
    db.connection.execute("INSERT INTO plugin_versions (plugin_id,version,artifact,digest,manifest,installed_ms,active) VALUES ('@a/ui','1','plugin.wasm','hash','{}',1,0)", []).unwrap();
    assert_eq!(revision(&db), before);
    db.connection
        .execute(
            "UPDATE plugin_versions SET active = 1 WHERE plugin_id = '@a/ui'",
            [],
        )
        .unwrap();
    let active = revision(&db);
    assert!(active > before);
    db.connection
        .execute(
            "UPDATE plugin_versions SET digest = 'changed' WHERE plugin_id = '@a/ui'",
            [],
        )
        .unwrap();
    assert!(revision(&db) > active);
}

#[test]
fn deletion_and_reinstallation_never_reuse_authority() {
    let mut db = database();
    let before = revision(&db);
    db.remove_plugin("@a/ui").unwrap();
    assert!(db.plugin_authority("@a/ui").unwrap().is_none());
    db.insert_plugin("@a/ui", true, true, "installed", 1, 1)
        .unwrap();
    assert!(revision(&db) > before);
    let before = revision(&db);
    db.invalidate_plugin_authority("@a/ui").unwrap();
    assert!(
        revision(&db) > before,
        "explicit reload has its own generation"
    );
}

#[test]
fn rolled_back_writes_and_exhausted_generations_never_publish_authority() {
    let db = database();
    let before = revision(&db);
    db.connection
        .execute_batch("BEGIN; UPDATE plugins SET enabled = 0 WHERE plugin_id = '@a/ui'; ROLLBACK;")
        .unwrap();
    assert_eq!(revision(&db), before);
    db.connection
        .execute(
            "UPDATE plugin_authority_clock SET revision = ?1",
            [i64::MAX],
        )
        .unwrap();
    assert!(db.set_plugin_enabled("@a/ui", false, 1).is_err());
    assert_eq!(revision(&db), before);
    assert!(db.plugin_authority("@a/ui").unwrap().unwrap().permits_ui());
}

#[test]
fn another_connection_observes_the_committed_generation_and_reopen_keeps_it() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.sqlite");
    let mut writer = SynraDb::open(&path).unwrap();
    writer.migrate().unwrap();
    writer
        .insert_plugin("@a/ui", true, true, "installed", 1, 1)
        .unwrap();
    let reader = SynraDb::open(&path).unwrap();
    let before = revision(&reader);
    writer.set_plugin_trusted("@a/ui", false, 1).unwrap();
    let after = revision(&reader);
    assert!(after > before);
    drop(writer);
    drop(reader);
    assert_eq!(revision(&SynraDb::open(&path).unwrap()), after);
}

#[test]
fn failed_bulk_consent_rolls_back_every_grant_and_the_authority_revision() {
    let db = database();
    let before = revision(&db);
    db.connection.execute_batch("CREATE TRIGGER fail_second_grant BEFORE INSERT ON plugin_grants WHEN NEW.capability = 'clipboard:read' BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    assert!(
        db.record_grants(
            "@a/ui",
            &[
                ("log:info".to_owned(), true),
                ("clipboard:read".to_owned(), true)
            ],
            1,
            "digest"
        )
        .is_err()
    );
    assert_eq!(revision(&db), before);
    assert!(db.plugin_grants("@a/ui").unwrap().is_empty());
}

#[test]
fn ui_snapshot_never_mixes_flags_and_grants_from_concurrent_commits() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("snapshots.sqlite");
    let mut writer = SynraDb::open(&path).unwrap();
    writer.migrate().unwrap();
    writer
        .insert_plugin("@a/ui", true, true, "installed", 1, 1)
        .unwrap();
    writer
        .record_grants("@a/ui", &[("log:info".to_owned(), true)], 1, "digest")
        .unwrap();
    let reader = SynraDb::open(&path).unwrap();
    let worker = std::thread::spawn(move || {
        for index in 0..100 {
            let granted = index % 2 == 0;
            let transaction = writer.connection.unchecked_transaction().unwrap();
            transaction
                .execute(
                    "UPDATE plugins SET enabled = ?1 WHERE plugin_id = '@a/ui'",
                    [granted],
                )
                .unwrap();
            transaction
                .execute(
                    "UPDATE plugin_grants SET granted = ?1 WHERE plugin_id = '@a/ui'",
                    [granted],
                )
                .unwrap();
            transaction.commit().unwrap();
        }
    });
    for _ in 0..200 {
        let snapshot = reader.plugin_ui_snapshot("@a/ui").unwrap().unwrap();
        assert_eq!(snapshot.grants.len(), 1);
        assert_eq!(
            snapshot.authority.enabled,
            snapshot.grants.first().unwrap().granted
        );
    }
    worker.join().unwrap();
}
