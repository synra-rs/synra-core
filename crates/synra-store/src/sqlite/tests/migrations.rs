use rusqlite::params;
use crate::db::{Health, MIGRATIONS, VERSION_TABLE_NAME};
use super::super::{DbError, SynraDb, migration_versions};
use super::migrated;

#[test]
fn a_fresh_database_migrates_to_the_latest_version() {
    let mut db = SynraDb::open_in_memory().expect("opens");
    assert_eq!(db.recorded_version().expect("reads"), None, "a fresh file has no version");

    let applied = db.migrate().expect("migrates");
    assert!(applied > 0);
    assert_eq!(
        db.recorded_version().expect("reads"),
        Some(SynraDb::known_version())
    );
}

#[test]
fn migrating_twice_applies_nothing_the_second_time() {
    // ★ A kernel that restarted would re-run every migration without this, and an idempotent-looking `CREATE TABLE`
    // is not idempotent: the second run fails with "table already exists", and the kernel would refuse to start on
    // any data directory it had already used.
    let mut db = migrated();
    assert_eq!(db.migrate().expect("migrates"), 0);
}

#[test]
fn every_table_the_migrations_declare_exists_afterwards() {
    // The property the rest of the module relies on: a query against a table named in `TABLES` has something to
    // query.
    let db = migrated();
    for table in crate::db::TABLES {
        assert!(db.has_table(table).expect("reads"), "{table} is missing");
    }
}

#[test]
fn the_migrations_create_the_columns_the_record_lists() {
    // ★ The end-to-end version of the assertion in `records`: a `SELECT` built from a column list has to name columns
    // the migration actually created. The check there is textual; this one asks the engine.
    let db = migrated();
    for (table, expected) in [
        ("paired_devices", crate::records::columns::DEVICE),
        ("devices_seen", crate::records::columns::SEEN_DEVICE),
        ("identity", crate::records::columns::IDENTITY),
        ("plugins", crate::records::columns::PLUGIN),
        ("config", crate::records::columns::CONFIG),
    ] {
        let statement = db
            .connection
            .prepare(&format!("SELECT * FROM {table} LIMIT 0"))
            .expect("prepares");
        let actual: Vec<String> = statement
            .column_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        // Every name the row's list gives must exist in the table, and the ones that exist must not appear in a
        // different relative order than the list gives them: the list is what a `SELECT` is built from, so a name it
        // has that the table does not is a query that fails only when it runs.
        let missing: Vec<&&str> =
            expected.iter().filter(|name| !actual.iter().any(|column| column == *name)).collect();
        assert!(missing.is_empty(), "{table} has no {missing:?}");
        let present: Vec<&str> = actual
            .iter()
            .map(String::as_str)
            .filter(|name| expected.contains(name))
            .collect();
        let wanted: Vec<&str> = expected
            .iter()
            .copied()
            .filter(|name| actual.iter().any(|column| column == name))
            .collect();
        // Both sides filtered to the same names, so this compares the *order* and nothing else. A column the migration
        // appended lands at the end of the table and must therefore be last in the list as well.
        assert_eq!(present, wanted, "{table}");
    }
}

#[test]
fn a_database_from_a_newer_build_is_refused() {
    // ★ A newer schema is a database written by a newer kernel. Opening it would run this build's migrations against
    // a shape they were not written for, and the damage is a schema that is neither version — which no later build
    // can repair because it cannot tell what it started from.
    let db = migrated();
    db.connection
        .execute(
            &format!("INSERT INTO {VERSION_TABLE_NAME} (version) VALUES (?1)"),
            params![SynraDb::known_version() + 5],
        )
        .expect("writes a future version");

    match db.refuse_a_future_schema() {
        Err(DbError::FromTheFuture { found, known }) => {
            assert_eq!(found, SynraDb::known_version() + 5);
            assert_eq!(known, SynraDb::known_version());
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_pragmas_are_applied_on_every_open() {
    // ★ `foreign_keys` is **per connection** in SQLite and defaults to off, so a connection opened without it
    // silently accepts orphaned rows — and the failure surfaces as data that cannot be joined rather than as an
    // error. Asserted rather than assumed, because "it is on by default" is exactly the belief that makes it wrong.
    let db = SynraDb::open_in_memory().expect("opens");
    let foreign_keys: i64 = db
        .connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .expect("reads");
    assert_eq!(foreign_keys, 1, "foreign keys are off");
}

#[test]
fn a_healthy_database_says_so() {
    let db = migrated();
    let health = db.health().expect("checks");
    assert_eq!(health, Health::Sound);
}

#[test]
fn the_foreign_key_cascade_the_schema_declares_is_enforced() {
    // ★ The pragma is only worth asserting if it does something. `plugin_versions` references `plugins` with
    // `ON DELETE CASCADE`, so removing a plugin has to take its versions — and without `foreign_keys = ON` the rows
    // would be left behind, pointing at a plugin that is gone.
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO plugins (plugin_id, enabled, trusted, health, installed_at_ms, updated_at_ms) \
             VALUES ('@a/b', 1, 1, 'healthy', 0, 0)",
            [],
        )
        .expect("a plugin");
    db.connection
        .execute(
            "INSERT INTO plugin_versions \
             (plugin_id, version, artifact, digest, manifest, installed_ms, active) \
             VALUES ('@a/b', '1.0.0', 'a.wasm', 'sha256-x', '{}', 0, 1)",
            [],
        )
        .expect("a version");

    db.connection.execute("DELETE FROM plugins WHERE plugin_id = '@a/b'", []).expect("removes");

    let left: i64 = db
        .connection
        .query_row("SELECT COUNT(*) FROM plugin_versions", [], |row| row.get(0))
        .expect("counts");
    assert_eq!(left, 0, "the cascade did not fire, so foreign keys are off");
}

#[test]
fn the_migration_versions_are_the_ones_the_contract_declares() {
    let versions = migration_versions();
    assert_eq!(versions.len(), MIGRATIONS.len());
    // Ascending and starting at one: the contract's own rule, asserted through the binding so a mismatch between
    // the two cannot be a difference in reading.
    assert_eq!(versions[0], 1);
    assert!(versions.windows(2).all(|pair| pair[0] < pair[1]), "{versions:?}");
}

#[test]
fn the_database_can_be_opened_from_a_file() {
    // The in-memory tests cover the logic; this covers the file path, which is the one a user's kernel uses.
    let path = std::env::temp_dir().join(format!("synra-db-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut db = SynraDb::open(&path).expect("opens");
    db.migrate().expect("migrates");
    assert!(db.has_table("identity").expect("reads"));
    drop(db);

    // Reopening finds the schema already there, which is the ordinary second start.
    let mut again = SynraDb::open(&path).expect("reopens");
    assert_eq!(again.migrate().expect("migrates"), 0);
    assert_eq!(again.recorded_version().expect("reads"), Some(SynraDb::known_version()));
    drop(again);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_clipboard_capability_is_renamed_to_the_name_the_gate_checks() {
    // ★ A data migration, so it is tested the only way a data migration can be: build a database at the version
    // **before** this step, put the legacy rows in, and run this step's own statements.
    //
    // The database is assembled from `MIGRATIONS` rather than from a hand-written schema — a fixture that spelled the
    // tables itself would drift from the migration list and stop noticing the step it is testing.
    let migration = MIGRATIONS
        .iter()
        .find(|migration| migration.version == 10)
        .expect("the clipboard migration");
    let db = SynraDb::open_in_memory().expect("opens");
    for earlier in MIGRATIONS.iter().filter(|migration| migration.version < 10) {
        for statement in earlier.statements {
            db.connection.execute_batch(statement).expect("an earlier migration");
        }
    }

    // A legacy grant row, a canonical row that must not be touched, and a plugin that somehow has both.
    db.insert_plugin("@acme/legacy", true, true, "installed", 1, 1).expect("a row");
    db.record_grants("@acme/legacy", &[("platform:clipboard:read".to_owned(), true)], 2, "digest")
        .expect("a legacy decision");

    db.insert_plugin("@acme/canonical", true, true, "installed", 1, 1).expect("a row");
    db.record_grants("@acme/canonical", &[("platform:read-clipboard".to_owned(), false)], 2, "digest")
        .expect("a canonical decision");

    db.insert_plugin("@acme/both", true, true, "installed", 1, 1).expect("a row");
    db.record_grants("@acme/both", &[("platform:read-clipboard".to_owned(), false)], 2, "digest")
        .expect("the canonical decision");
    db.record_grants("@acme/both", &[("platform:clipboard:read".to_owned(), true)], 2, "digest")
        .expect("and the legacy one");

    for statement in migration.statements {
        db.connection.execute_batch(statement).expect("the migration applies");
    }

    let legacy = db.plugin_grants("@acme/legacy").expect("the decisions");
    assert_eq!(legacy.len(), 1, "{legacy:?}");
    assert_eq!(legacy[0].capability, "platform:read-clipboard");
    assert!(legacy[0].granted, "the user's answer survived the rename");

    let canonical = db.plugin_grants("@acme/canonical").expect("the decisions");
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].capability, "platform:read-clipboard");
    assert!(!canonical[0].granted, "a refusal is not turned into a grant");

    // The collision the primary key would otherwise refuse: one row, and it is the canonical one's decision.
    let both = db.plugin_grants("@acme/both").expect("the decisions");
    assert_eq!(both.len(), 1, "the rename left two rows: {both:?}");
    assert_eq!(both[0].capability, "platform:read-clipboard");
    assert!(!both[0].granted, "the canonical decision was replaced by the legacy one");
}
