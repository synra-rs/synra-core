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
