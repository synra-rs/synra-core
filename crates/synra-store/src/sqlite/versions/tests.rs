//! Which row is the one a plan should compare.

use super::{PluginVersionRecord, SynraDb};
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

    db.record_plugin_version(&PluginVersionRecord { plugin_id: "@acme/hello", version: "1.2.3", artifact: "plugin.wasm", digest: "sha256-abc", manifest: "{}", installed_ms: 1_000, ..Default::default() })
        .expect("a recorded version");

    assert_eq!(
        db.active_plugin_version("@acme/hello").expect("a read"),
        Some(("1.2.3".to_owned(), "sha256-abc".to_owned()))
    );
}

#[test]
fn the_active_version_names_its_signer() {
    // ★ The version row knew what bytes ran and nothing about who signed them; revocation and a safe automatic update
    // both need the key, not only the publisher name.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/hello",
        version: "1.2.3",
        artifact: "plugin.wasm",
        digest: "sha256-abc",
        manifest: "{}",
        publisher_id: Some("@acme"),
        fingerprint: Some("AB12 CD34 EF56 7890"),
        installed_ms: 1_000,
    })
    .expect("a recorded version");

    let active = db.active_plugin("@acme/hello").expect("a read").expect("an active version");

    assert_eq!(active.publisher_id.as_deref(), Some("@acme"));
    assert_eq!(active.fingerprint.as_deref(), Some("AB12 CD34 EF56 7890"));
}

#[test]
fn only_active_versions_signed_by_a_key_are_named() {
    // ★ The old version of a plugin is still on disk for rollback; it is not what is running, so revoking its key must
    // not name the plugin. The query is the index this migration exists for.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    for plugin in ["@acme/one", "@acme/two"] {
        db.insert_plugin(plugin, true, true, "active", 1_000, 1_000).expect("a plugin");
    }
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/one",
        version: "1.0.0",
        manifest: "{}",
        fingerprint: Some("KEY A"),
        installed_ms: 1_000,
        ..Default::default()
    })
    .expect("one");
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/two",
        version: "1.0.0",
        manifest: "{}",
        fingerprint: Some("KEY B"),
        installed_ms: 1_000,
        ..Default::default()
    })
    .expect("two, first");
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/two",
        version: "2.0.0",
        manifest: "{}",
        fingerprint: Some("KEY A"),
        installed_ms: 2_000,
        ..Default::default()
    })
    .expect("two, second");

    assert_eq!(
        db.active_plugins_by_fingerprint("KEY A").expect("a read"),
        vec!["@acme/one".to_owned(), "@acme/two".to_owned()]
    );
    assert!(
        db.active_plugins_by_fingerprint("KEY B").expect("a read").is_empty(),
        "the inactive version's signer names nothing"
    );
}

#[test]
fn the_active_version_names_the_artifact_it_installed() {
    // ★ The plan reads two columns; sending reads three. The artifact is a **file name** relative to the plugin's
    // directory — a path here would point into whatever data directory the row was written in.
    let (db, plugin) = with_two_versions();

    let active = db.active_plugin(&plugin).expect("a read").expect("an active version");

    assert_eq!(active.version, "2.0.0");
    assert_eq!(active.artifact, "plugin.wasm");
    assert_eq!(active.digest, "sha256-new");
    // And the older reader still agrees, because both are one query.
    assert_eq!(
        db.active_plugin_version(&plugin).expect("a read"),
        Some((active.version, active.digest))
    );
}

#[test]
fn a_ui_only_plugin_has_an_empty_artifact_name() {
    // The install records "" for a plugin with no headless half. The reader reports it rather than inventing a name; the
    // caller that needs bytes has to say what that means.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");
    db.record_plugin_version(&PluginVersionRecord { plugin_id: "@acme/hello", version: "1.2.3", artifact: "", digest: "", manifest: "{}", installed_ms: 1_000, ..Default::default() })
        .expect("a version with no artifact");

    let active = db.active_plugin("@acme/hello").expect("a read").expect("an active version");

    assert_eq!(active.artifact, "");
    assert_eq!(active.digest, "");
}

#[test]
fn recording_a_second_version_moves_the_active_row_and_keeps_the_old_one() {
    // ★ Two facts in one test, because they are the same act. Exactly one row is active — a second active row would make "which
    // version is this device running" have two answers — and the previous row survives, because the directory it describes does.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "active", 1_000, 1_000).expect("a plugin");

    db.record_plugin_version(&PluginVersionRecord { plugin_id: "@acme/hello", version: "1.0.0", artifact: "plugin.wasm", digest: "sha256-old", manifest: "{}", installed_ms: 1_000, ..Default::default() })
        .expect("the first version");
    db.record_plugin_version(&PluginVersionRecord { plugin_id: "@acme/hello", version: "2.0.0", artifact: "plugin.wasm", digest: "sha256-new", manifest: "{}", installed_ms: 2_000, ..Default::default() })
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
