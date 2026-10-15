use rusqlite::params;

use crate::db::{Health, MIGRATIONS, VERSION_TABLE_NAME};
use crate::records::RowError;

use super::{DbError, SynraDb, migration_versions};

/// A database with every migration applied.
fn migrated() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db
}

// ── Opening and migrating ─────────────────────────────────────────────────────────────────────

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

// ── Reading ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_empty_database_has_no_devices_and_that_is_not_an_error() {
    // `synra db dump` and a fresh installation both need this to be an empty list rather than a failure.
    let db = migrated();
    assert!(db.paired_devices().expect("reads").is_empty());
    assert!(db.seen_devices().expect("reads").is_empty());
    assert!(db.plugins().expect("reads").is_empty());
    assert!(db.config().expect("reads").is_empty());
    assert!(db.identity().expect("reads").is_none());
}

#[test]
fn a_paired_device_round_trips_through_the_engine() {
    // ★ The whole point of the record types: a row written by SQL and read back by the positional reader has to
    // arrive in the right fields. A swap between two `TEXT` columns would show up here as a name that is a platform.
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO paired_devices \
             (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
             VALUES ('dev_a', 'Laptop', 'windows', '[\"eventStream\"]', 1000, 2000, 0)",
            [],
        )
        .expect("a device");

    let devices = db.paired_devices().expect("reads");
    assert_eq!(devices.len(), 1);
    let device = &devices[0];
    assert_eq!(device.device_id, "dev_a");
    assert_eq!(device.display_name, "Laptop");
    assert_eq!(device.platform, "windows");
    assert_eq!(device.features, vec!["eventStream"]);
    assert_eq!(device.paired_at_ms, 1_000);
    assert_eq!(device.last_seen_ms, 2_000);
    assert!(!device.blocked);
}

#[test]
fn a_blocked_device_reads_back_blocked() {
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO paired_devices \
             (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
             VALUES ('dev_a', 'N', 'P', '[]', 0, 0, 1)",
            [],
        )
        .expect("a device");

    let device = db.paired_devices().expect("reads").remove(0);
    assert!(device.blocked);
    assert!(!device.is_usable());
}

#[test]
fn devices_come_back_in_a_stable_order() {
    // ★ Two runs of `synra devices` have to agree, or a diff of two reports is noise and a test of one is flaky.
    let db = migrated();
    for (id, name) in [("d2", "Zeta"), ("d1", "Alpha"), ("d3", "Alpha")] {
        db.connection
            .execute(
                "INSERT INTO paired_devices \
                 (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
                 VALUES (?1, ?2, 'p', '[]', 0, 0, 0)",
                params![id, name],
            )
            .expect("a device");
    }

    let order: Vec<String> = db
        .paired_devices()
        .expect("reads")
        .into_iter()
        .map(|device| device.device_id)
        .collect();
    // By name, then by id — so the two `Alpha`s are ordered by the key rather than by insertion.
    assert_eq!(order, vec!["d1", "d3", "d2"]);
}

#[test]
fn a_identity_round_trips() {
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
             VALUES (1, 'self', 'This machine', 'linux', 42)",
            [],
        )
        .expect("an identity");

    let identity = db.identity().expect("reads").expect("an identity");
    assert_eq!(identity.device_id, "self");
    assert_eq!(identity.display_name, "This machine");
    assert_eq!(identity.created_at_ms, 42);
}

#[test]
fn the_schema_allows_only_one_identity_row() {
    // ★ The `CHECK (id = 1)` is what makes "this device's identity" a single answer. Without it a second write would
    // add a second row, and the reader — which asks for `id = 1` — would silently keep using the first.
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
             VALUES (1, 'self', 'A', 'linux', 0)",
            [],
        )
        .expect("the first");
    let second = db.connection.execute(
        "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
         VALUES (2, 'other', 'B', 'linux', 0)",
        [],
    );
    assert!(second.is_err(), "the schema allowed a second identity row");
}

#[test]
fn a_plugin_round_trips_and_knows_whether_to_run() {
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO plugins (plugin_id, enabled, trusted, health, installed_at_ms, updated_at_ms) \
             VALUES ('@acme/hello', 1, 0, 'healthy', 10, 20)",
            [],
        )
        .expect("a plugin");

    let plugin = db.plugins().expect("reads").remove(0);
    assert_eq!(plugin.plugin_id, "@acme/hello");
    assert!(plugin.enabled);
    assert!(!plugin.trusted);
    assert!(!plugin.should_run(), "an untrusted plugin should not run");
    assert_eq!(plugin.health, "healthy");
    assert_eq!(plugin.updated_at_ms, 20);
}

// ── Enabling, trusting and grants ─────────────────────────────────────────────────────────────

/// A database with one plugin in it, untrusted and off.
///
/// A helper because four of the tests below are about the *second* write, and a test whose setup is three lines of SQL
/// spends more of itself on setup than on what it is checking.
fn with_plugin() -> SynraDb {
    let db = migrated();
    db.insert_plugin("@acme/hello", false, false, "healthy", 10, 20).expect("a plugin");
    db
}

#[test]
fn a_plugin_can_be_switched_off_and_on_again() {
    let db = with_plugin();

    assert!(db.set_plugin_enabled("@acme/hello", true, 30).expect("enables"), "the plugin is there");
    let after = db.plugins().expect("reads").remove(0);
    assert!(after.enabled, "the flag reached the row");
    assert_eq!(after.updated_at_ms, 30, "and the time it changed");

    db.set_plugin_enabled("@acme/hello", false, 40).expect("disables");
    assert!(!db.plugins().expect("reads").remove(0).enabled, "and it can be switched back off");
}

#[test]
fn enabling_a_plugin_that_is_not_installed_says_so_rather_than_succeeding() {
    // ★ The fault this catches: `UPDATE` on a missing row changes nothing and reports success, so a caller that
    // believed the `Ok(())` would show the user a plugin that is still off.
    let db = with_plugin();
    assert!(!db.set_plugin_enabled("@acme/nope", true, 30).expect("the write itself is fine"));
    assert_eq!(db.plugins().expect("reads").len(), 1, "and nothing was invented");
}

#[test]
fn trusting_is_not_the_same_act_as_enabling() {
    let db = with_plugin();
    db.set_plugin_enabled("@acme/hello", true, 30).expect("enables");
    let plugin = db.plugins().expect("reads").remove(0);
    assert!(
        !plugin.should_run(),
        "an enabled plugin nobody has trusted must not run — this is what consent is for"
    );

    db.set_plugin_trusted("@acme/hello", true, 31).expect("trusts");
    assert!(
        db.plugins().expect("reads").remove(0).should_run(),
        "and once both are true it runs"
    );
}

#[test]
fn grants_read_back_what_was_written_against_a_manifest() {
    let db = with_plugin();
    // Written through the connection rather than a method, because there is deliberately no writer yet — see the note
    // beside `plugin_grants`. A test that only ever used the reader could not tell the reader from a table that is
    // always empty, so this one writes first and checks the digest survived.
    db.connection
        .execute(
            "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
             VALUES ('@acme/hello', 'net:*.read', 1, 50, 'sha256:abc')",
            [],
        )
        .expect("a grant");
    db.connection
        .execute(
            "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
             VALUES ('@acme/hello', 'store:*.write', 0, 50, 'sha256:abc')",
            [],
        )
        .expect("a refusal");

    let read = db.plugin_grants("@acme/hello").expect("reads");
    assert_eq!(read.len(), 2);
    // Sorted by capability, so the order is the same on every device that read the same decisions.
    assert_eq!(read[0].capability, "net:*.read");
    assert!(read[0].granted);
    assert_eq!(read[0].manifest_digest, "sha256:abc", "the digest survived, which is what an upgrade compares");
    assert!(!read[1].granted, "a refusal is stored as a refusal, not as an absence");
}

#[test]
fn a_plugin_with_no_decisions_has_an_empty_list_rather_than_an_error() {
    let db = with_plugin();
    assert!(db.plugin_grants("@acme/hello").expect("reads").is_empty());
}

#[test]
fn a_plugins_grants_are_not_another_plugins_grants() {
    let db = with_plugin();
    db.insert_plugin("@acme/other", true, true, "healthy", 10, 20).expect("a second plugin");
    db.connection
        .execute(
            "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
             VALUES ('@acme/hello', 'net:*.read', 1, 50, 'sha256:abc')",
            [],
        )
        .expect("a grant");
    assert!(
        db.plugin_grants("@acme/other").expect("reads").is_empty(),
        "the filter is by plugin, not by table"
    );
}

#[test]
fn a_config_value_round_trips_as_json() {
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO config (key, value, updated_ms) VALUES ('ui.locale', '\"zh\"', 7)",
            [],
        )
        .expect("a setting");

    let entry = db.config().expect("reads").remove(0);
    assert_eq!(entry.key, "ui.locale");
    assert_eq!(entry.json().expect("json"), serde_json::json!("zh"));
}

#[test]
fn a_boolean_column_the_schema_forbids_is_reported_rather_than_read_as_true() {
    // ★ The `CHECK (x IN (0, 1))` is enforced by the engine, so this row can only arrive from a corrupt file or a
    // table created outside the migrations — which is exactly the case a reader must not interpret. The assertion is
    // that the schema refuses it, so the reader never sees it.
    let db = migrated();
    let refused = db.connection.execute(
        "INSERT INTO paired_devices \
         (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
         VALUES ('d', 'n', 'p', '[]', 0, 0, 2)",
        [],
    );
    assert!(refused.is_err(), "the schema allowed blocked = 2");
}

#[test]
fn the_counts_report_every_table_including_an_absent_one() {
    // A table the migration has not created is reported as absent rather than as an error, because `synra db dump`
    // on a fresh file is a legitimate thing to run.
    let empty = SynraDb::open_in_memory().expect("opens");
    let counts = empty.counts().expect("counts");
    assert_eq!(counts.len(), crate::db::TABLES.len());
    assert!(counts.iter().all(|(_, count)| count.is_none()), "a fresh file has no tables");

    let db = migrated();
    let counts = db.counts().expect("counts");
    assert!(counts.iter().all(|(_, count)| count.is_some()), "{counts:?}");
    assert!(counts.iter().all(|(_, count)| count == &Some(0)));
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
fn every_error_explains_itself() {
    let errors = [
        DbError::Open { path: std::path::PathBuf::from("/tmp/x"), why: "denied".to_owned() },
        DbError::Statement { why: "no such table".to_owned() },
        DbError::FromTheFuture { found: 9, known: 3 },
        DbError::Row(RowError::Missing { column: "device_id" }),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And the future-schema message names both versions, because "incompatible" alone leaves the user with nothing.
    let text = errors[2].to_string();
    assert!(text.contains('9') && text.contains('3'), "{text}");
}


// ── Pairing ───────────────────────────────────────────────────────────────────────────────────

/// A pairing record, which is what the write takes.
///
/// A helper rather than a literal at each call site, because what most of these tests are about is the token and the
/// address rather than the platform and the features.
fn paired(
    device_id: &str,
    display_name: &str,
    token: &str,
    address: Option<&str>,
    now_ms: i64,
) -> crate::sqlite::Paired {
    crate::sqlite::Paired {
        device_id: device_id.to_owned(),
        display_name: display_name.to_owned(),
        platform: "windows".to_owned(),
        features: "[]".to_owned(),
        link_token: token.to_owned(),
        address: address.map(str::to_owned),
        paired_at_ms: now_ms,
    }
}

#[test]
fn pairing_a_device_stores_the_token_a_later_link_must_present() {
    let db = migrated();

    assert_eq!(db.link_token_for("dev-1").expect("queries"), None, "nothing is paired to begin with");
    assert!(!db.is_paired_with("dev-1").expect("queries"));

    let mut record = paired("dev-1", "Laptop", "aa11", Some("10.0.0.4:51000"), 1_700);
    record.features = r#"["TransferResume"]"#.to_owned();
    db.pair_device(&record).expect("pairs");

    assert_eq!(db.link_token_for("dev-1").expect("queries").as_deref(), Some("aa11"));
    assert!(db.is_paired_with("dev-1").expect("queries"));
    assert_eq!(db.paired_devices().expect("lists")[0].address.as_deref(), Some("10.0.0.4:51000"));
}

#[test]
fn pairing_without_an_address_stores_none() {
    // An empty address is "this side has none", not "the address is the empty string": a caller that pairs a device it
    // reached over something other than a socket — or a test — must not leave a value behind that a device list would
    // then render as a blank line where an address belongs.
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", "tok", None, 1_000)).expect("pairs");

    assert_eq!(db.paired_devices().expect("lists")[0].address, None);
}

#[test]
fn pairing_the_same_device_again_replaces_its_token() {
    // The ordinary case, not an exception: a device is reset, its token is refused as stale, and the user pairs it
    // again. An insert that failed the second time would turn a routine action into an error.
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", "first", None, 1_000)).expect("pairs");
    db.pair_device(&paired("dev-1", "Laptop renamed", "second", None, 2_000)).expect("pairs again");

    assert_eq!(db.link_token_for("dev-1").expect("queries").as_deref(), Some("second"));
    assert_eq!(db.paired_devices().expect("lists").len(), 1, "pairing again must not add a second row");
    assert_eq!(db.paired_devices().expect("lists")[0].display_name, "Laptop renamed");
}

#[test]
fn pairing_again_clears_a_block() {
    // A device the user blocked and then deliberately paired again is a decision the user has reversed. Leaving the
    // block in place would make the second pairing appear to succeed and then refuse every link.
    //
    // The block is set with SQL rather than through a method because no method exists: nothing in the kernel blocks a
    // device yet, so a `set_device_blocked` would be unused public API written only to make this test read nicely.
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", "tok", None, 1_000)).expect("pairs");
    db.connection
        .execute("UPDATE paired_devices SET blocked = 1 WHERE device_id = 'dev-1'", [])
        .expect("blocks");
    assert!(!db.is_paired_with("dev-1").expect("queries"), "a blocked device is not usable");

    db.pair_device(&paired("dev-1", "Laptop", "tok2", None, 2_000)).expect("pairs again");
    assert!(db.is_paired_with("dev-1").expect("queries"));
}

#[test]
fn unpairing_removes_the_token_with_the_pairing() {
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", "tok", None, 1_000)).expect("pairs");

    assert!(db.unpair_device("dev-1").expect("unpairs"));
    assert_eq!(db.link_token_for("dev-1").expect("queries"), None);
    assert!(!db.unpair_device("dev-1").expect("unpairs again"), "the second removal removes nothing");
}

#[test]
fn a_pairing_from_before_tokens_reports_no_token_rather_than_failing() {
    // Migration 6 added the column as nullable, so a row written before it exists with a null token. Reading that must
    // be an answer — "paired, but must pair again" — not an error, because an error would refuse a link the user made.
    let db = migrated();
    db.pair_device(&paired("dev-1", "Laptop", "tok", None, 1_000)).expect("pairs");
    db.connection
        .execute("UPDATE paired_devices SET link_token = NULL WHERE device_id = 'dev-1'", [])
        .expect("clears the token");

    assert_eq!(db.link_token_for("dev-1").expect("queries"), None);
    assert!(db.is_paired_with("dev-1").expect("queries"), "the pairing still exists");
}
