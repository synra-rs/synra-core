//! Which row is the one a plan should compare.

use super::SynraDb;
use rusqlite::params;

/// A database with one plugin installed at two versions, the older one active.
fn with_two_versions() -> (SynraDb, String) {
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");
    db.connection
        .execute(
            "INSERT INTO plugin_versions (plugin_id, version, artifact, digest, manifest, installed_ms, active) \
             VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6)",
            params!["@acme/hello", "1.0.0", "plugin.wasm", "sha256-old", 1_000i64, 0i64],
        )
        .expect("an older version");
    db.connection
        .execute(
            "INSERT INTO plugin_versions (plugin_id, version, artifact, digest, manifest, installed_ms, active) \
             VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6)",
            params!["@acme/hello", "2.0.0", "plugin.wasm", "sha256-new", 2_000i64, 1i64],
        )
        .expect("a newer version");
    (db, "@acme/hello".to_owned())
}

#[test]
fn the_active_version_is_the_one_reported_even_when_a_newer_row_exists() {
    // ★ The failure this guards: reporting the newest row would tell a peer it can skip a transfer for a version this device is not
    // running — the one case where a wrong plan breaks a working plugin.
    let (db, plugin) = with_two_versions();

    let active = db.active_plugin_version(&plugin).expect("a read");

    assert_eq!(active, Some(("2.0.0".to_owned(), "sha256-new".to_owned())));
}

#[test]
fn a_plugin_with_no_active_row_answers_nothing() {
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");

    assert_eq!(db.active_plugin_version("@acme/hello").expect("a read"), None);
    assert_eq!(db.active_plugin_version("@acme/absent").expect("a read"), None);
}

#[test]
fn a_recorded_version_is_the_one_that_counts() {
    // The writer that was missing: `active_plugin_version` had a reader and no production writer, so every plan said "this device
    // has nothing". A recorded install is the fact that changes that answer.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");

    db.record_plugin_version("@acme/hello", "1.2.3", "plugin.wasm", "sha256-abc", "{}", 1_000)
        .expect("a recorded version");

    assert_eq!(
        db.active_plugin_version("@acme/hello").expect("a read"),
        Some(("1.2.3".to_owned(), "sha256-abc".to_owned()))
    );
}

#[test]
fn recording_a_second_version_moves_the_active_row_and_keeps_the_old_one() {
    // ★ Two facts in one test, because they are the same act. Exactly one row is active — a second active row would make "which
    // version is this device running" have two answers — and the previous row survives, because the directory it describes does.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");

    db.record_plugin_version("@acme/hello", "1.0.0", "plugin.wasm", "sha256-old", "{}", 1_000)
        .expect("the first version");
    db.record_plugin_version("@acme/hello", "2.0.0", "plugin.wasm", "sha256-new", "{}", 2_000)
        .expect("the second version");

    assert_eq!(
        db.active_plugin_version("@acme/hello").expect("a read"),
        Some(("2.0.0".to_owned(), "sha256-new".to_owned()))
    );

    let (versions, active) = db
        .connection
        .query_row(
            "SELECT COUNT(*), SUM(active) FROM plugin_versions WHERE plugin_id = ?1",
            params!["@acme/hello"],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("a count");
    assert_eq!(versions, 2, "the older version is kept for a rollback");
    assert_eq!(active, 1, "exactly one row is the one in effect");
}
