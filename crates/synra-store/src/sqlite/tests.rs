use rusqlite::params;

use crate::db::{Health, MIGRATIONS, VERSION_TABLE_NAME};
use crate::records::{RowError, SyncLogRow};

use super::{ConfigChange, DbError, SynraDb, migration_versions};

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

// ── Devices seen but not paired ───────────────────────────────────────────────────────────────

/// A sighting of one device, with the values a test varies.
fn sighting(name: &str, seen_at_ms: i64) -> crate::Seen {
    crate::Seen {
        device_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        display_name: name.to_owned(),
        platform: "linux".to_owned(),
        seen_at_ms,
        source: "broadcast".to_owned(),
    }
}

#[test]
fn a_device_that_was_heard_from_is_remembered() {
    let db = migrated();
    db.record_seen_device(&sighting("Study PC", 500)).expect("records");

    let seen = db.seen_devices().expect("reads");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].display_name, "Study PC");
    assert_eq!(seen[0].source, "broadcast");
    assert_eq!(seen[0].first_seen_ms, 500);
    assert_eq!(seen[0].last_seen_ms, 500);
}

#[test]
fn hearing_the_same_device_twice_is_one_row_and_not_two() {
    // ★ The reason this is an upsert keyed on the device.
    //
    // Discovery announces the same machine on every scan; one row per announcement is a table that grows without bound
    // for a device sitting on the same desk.
    let db = migrated();
    db.record_seen_device(&sighting("Study PC", 500)).expect("first");
    db.record_seen_device(&sighting("Study PC", 900)).expect("second");

    let seen = db.seen_devices().expect("reads");
    assert_eq!(seen.len(), 1, "one device is one row");
    assert_eq!(seen[0].last_seen_ms, 900, "and the latest sighting is the one kept");
}

#[test]
fn the_first_sighting_is_never_moved_forward() {
    let db = migrated();
    db.record_seen_device(&sighting("Study PC", 500)).expect("first");
    db.record_seen_device(&sighting("Study PC", 900)).expect("second");
    assert_eq!(
        db.seen_devices().expect("reads").remove(0).first_seen_ms,
        500,
        "a device seen again has been seen continuously, and the first sighting is the fact a user wants"
    );
}

#[test]
fn an_older_sighting_arriving_late_does_not_move_the_last_seen_backwards() {
    // ★ The `MAX` in the upsert, which is the whole reason that clause is there.
    //
    // Discovery listens on more than one path and the announcements do not arrive in time order, so a sighting from a
    // slow path can land after a newer one. Without this, "last seen" goes backwards and a device that is present looks
    // like it has not been heard from for longer than it has — which is what makes a working device get shown as stale.
    let db = migrated();
    db.record_seen_device(&sighting("Study PC", 900)).expect("the newer one");
    db.record_seen_device(&sighting("Study PC", 500)).expect("the older one, arriving late");

    assert_eq!(db.seen_devices().expect("reads").remove(0).last_seen_ms, 900);
}

#[test]
fn a_device_that_changes_its_name_is_still_one_row() {
    let db = migrated();
    db.record_seen_device(&sighting("Old name", 500)).expect("first");
    db.record_seen_device(&sighting("New name", 900)).expect("second");
    let seen = db.seen_devices().expect("reads");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].display_name, "New name", "the current name wins");
}

#[test]
fn a_paired_device_that_is_also_heard_from_keeps_both_records() {
    // The two tables are separate and neither cascades into the other: pairing must not erase the evidence that a
    // device was on the network before, and being heard from must not unpair it.
    let db = migrated();
    db.pair_device(&crate::Paired {
        device_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        display_name: "Study PC".to_owned(),
        platform: "linux".to_owned(),
        features: "[]".to_owned(),
        link_token: "token".to_owned(),
        address: None,
        paired_at_ms: 400,
    })
    .expect("pairs");
    db.record_seen_device(&sighting("Study PC", 500)).expect("records a sighting");

    assert_eq!(db.paired_devices().expect("reads").len(), 1, "still paired");
    assert_eq!(db.seen_devices().expect("reads").len(), 1, "and still heard from");
}

// ── Settings ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_publisher_is_recorded_once_and_a_decision_survives_later_sightings() {
    // ★ "Seen" is not "trusted": an install may record that a key signed a package, and only a user decision may promote
    // it. A second sighting must not reset a decision either — that would make every update forget the answer.
    let db = migrated();
    assert!(db.publishers().expect("reads").is_empty(), "a fresh install has met nobody");

    db.record_publisher("@acme", "AB12 CD34 EF56 7890", "a2V5", 1_000)
        .expect("records");
    let rows = db.publishers().expect("reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].trust, crate::TRUST_SEEN);
    assert_eq!(rows[0].decided_ms, None);

    assert!(!db.set_publisher_trust("@acme", "wrong key", crate::TRUST_TRUSTED, 1_500).expect("stale key"));
    assert!(!db.set_publisher_trust("@acme", "AB12 CD34 EF56 7890", "maybe", 1_500).expect("invalid trust"));
    assert_eq!(db.publishers().expect("rows")[0].decided_ms, None);
    assert!(db.set_publisher_trust("@acme", "AB12 CD34 EF56 7890", crate::TRUST_TRUSTED, 2_000).expect("updates"));
    db.record_publisher("@acme", "AB12 CD34 EF56 7890", "a2V5", 3_000)
        .expect("records again");
    let rows = db.publishers().expect("reads");
    assert_eq!(rows[0].trust, crate::TRUST_TRUSTED, "the decision survives");
    assert_eq!(rows[0].decided_ms, Some(2_000));

    // A decision about a publisher nobody has met is not a decision: there is no row for the installer to consult.
    assert!(!db.set_publisher_trust("@ghost", "AB12 CD34 EF56 7890", crate::TRUST_TRUSTED, 4_000).expect("updates"));
}

#[test]
fn a_setting_written_as_a_string_reads_back_as_a_string_not_as_text() {
    // ★ The reason `set_config` serialises rather than taking text.
    //
    // The column holds JSON text, so a caller who wrote `value.to_string()` would store `Study PC` — which parses as
    // nothing at all, and fails much later in a settings screen rather than here.
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 7).expect("writes");

    let entry = db.config().expect("reads").remove(0);
    assert_eq!(entry.key, "ui.locale");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&entry.value).expect("parses"),
        serde_json::json!("zh")
    );
}

#[test]
fn writing_a_setting_twice_is_one_key_and_the_second_wins() {
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 7).expect("first");
    db.set_config("ui.locale", &serde_json::json!("en"), 9).expect("second");

    let all = db.config().expect("reads");
    assert_eq!(all.len(), 1, "a key is a key");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&all[0].value).expect("parses"),
        serde_json::json!("en"),
        "and the later write is the one that stands"
    );
    assert_eq!(all[0].updated_ms, 9, "with the time it was written");
}

#[test]
fn a_setting_of_every_json_shape_round_trips() {
    // A configuration screen edits numbers, booleans, lists and objects — a writer that only handled strings would be
    // useless for all four, so each is checked rather than assuming.
    let db = migrated();
    let cases = [
        ("a.number", serde_json::json!(42)),
        ("a.fraction", serde_json::json!(-0.5)),
        ("a.boolean", serde_json::json!(true)),
        ("a.list", serde_json::json!(["x", "y"])),
        ("an.object", serde_json::json!({"k": "v"})),
        ("a.null", serde_json::Value::Null),
    ];
    for (key, value) in &cases {
        db.set_config(key, value, 1).expect("writes");
    }

    let all = db.config().expect("reads");
    assert_eq!(all.len(), cases.len());
    for (key, value) in &cases {
        let row = all.iter().find(|row| row.key == *key).expect("the row is there");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&row.value).expect("parses"),
            *value,
            "{key} came back as something else"
        );
    }
}

#[test]
fn removing_a_setting_reports_whether_there_was_one() {
    // ★ Why the count is returned at all.
    //
    // A `DELETE` that matches nothing reports success. A command that answered "done" for a key the user had already
    // removed would be indistinguishable from one that actually removed it.
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 1).expect("writes");

    assert!(db.unset_config("ui.locale").expect("removes"), "it was there");
    assert!(db.config().expect("reads").is_empty());
    assert!(!db.unset_config("ui.locale").expect("removes"), "the second time it was not");
}

#[test]
fn a_batch_writes_every_key_it_was_given() {
    let db = migrated();
    db.apply_config(
        &[
            ConfigChange { key: "ui.locale".to_owned(), value: Some(serde_json::json!("zh")) },
            ConfigChange { key: "sync.enabled".to_owned(), value: Some(serde_json::json!(false)) },
        ],
        11,
    )
    .expect("applies");

    let all = db.config().expect("reads");
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|row| row.updated_ms == 11), "one clock, not two");
}

#[test]
fn a_batch_can_set_and_remove_at_the_same_time() {
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 1).expect("writes");
    db.set_config("ui.theme", &serde_json::json!("dark"), 1).expect("writes");

    db.apply_config(
        &[
            ConfigChange { key: "ui.locale".to_owned(), value: Some(serde_json::json!("en")) },
            ConfigChange { key: "ui.theme".to_owned(), value: None },
        ],
        12,
    )
    .expect("applies");

    let all = db.config().expect("reads");
    assert_eq!(all.len(), 1, "the theme is gone");
    assert_eq!(all[0].key, "ui.locale", "and the locale was replaced, not merely added");
}

#[test]
fn an_empty_batch_changes_nothing_and_is_not_an_error() {
    // A settings screen that renders before the user has touched anything will send this, and answering it with an error
    // would make the screen look broken on open.
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 1).expect("writes");
    db.apply_config(&[], 99).expect("applies");

    assert_eq!(db.config().expect("reads").len(), 1);
    assert_eq!(db.config().expect("reads").remove(0).updated_ms, 1, "and it was not rewritten");
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
    for (table, count) in &counts {
        assert_eq!(
            *count,
            Some(i64::from(table == "plugin_authority_clock")),
            "{table}"
        );
    }
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

/// A sighting of a device the fixture names, at a moment it names.
///
/// The `sighting` fixture above has a fixed identifier, which is right for the upsert tests and wrong for a retention one:
/// "keep the most recent three" needs more than one device.
fn heard(name: &str, at_ms: i64) -> crate::Seen {
    crate::Seen {
        device_id: format!("{name:0>8}-0000-4000-8000-000000000000").replace(' ', "0"),
        display_name: name.to_owned(),
        platform: "linux".to_owned(),
        seen_at_ms: at_ms,
        source: "broadcast".to_owned(),
    }
}

#[test]
fn a_network_with_more_devices_than_the_ceiling_keeps_the_most_recent() {
    // ★ The rule the design gives this table: keep the most recent 500. Discovery announces every machine on the network, so
    // on a shared one this table is the GC target that genuinely fills up — and until this existed nothing emptied it.
    let db = migrated();
    for (index, name) in ["one", "two", "three", "four", "five"].iter().enumerate() {
        db.record_seen_device(&heard(name, 1_000 + (index as i64) * 10)).expect("heard");
    }

    let removed = db.forget_seen_devices_beyond(3).expect("collected");

    assert_eq!(removed, 2, "the two oldest went");
    let left: Vec<String> = db
        .seen_devices()
        .expect("listed")
        .into_iter()
        .map(|row| row.display_name)
        .collect();
    // Listed newest first, so the surviving three are in that order.
    assert_eq!(left, vec!["five".to_owned(), "four".to_owned(), "three".to_owned()]);
}

#[test]
fn a_network_smaller_than_the_ceiling_loses_nothing() {
    // The ordinary case, and the one that runs every hour on a home network.
    let db = migrated();
    db.record_seen_device(&heard("one", 1_000)).expect("heard");
    db.record_seen_device(&heard("two", 2_000)).expect("heard");

    assert_eq!(db.forget_seen_devices_beyond(500).expect("collected"), 0);
    assert_eq!(db.seen_devices().expect("listed").len(), 2);
}

#[test]
fn devices_heard_in_the_same_millisecond_are_kept_by_a_stable_rule() {
    // ★ Why the ordering has an identifier in it. Without the tie-break, which of two devices heard in the same
    // millisecond survives would depend on the order SQLite happened to return them — so two runs of the same sweep could
    // keep different rows, and no test could assert anything about it.
    let db = migrated();
    for name in ["alpha", "bravo", "charlie"] {
        db.record_seen_device(&heard(name, 5_000)).expect("heard");
    }

    let first = db.forget_seen_devices_beyond(2).expect("collected");
    let surviving: Vec<String> = db
        .seen_devices()
        .expect("listed")
        .into_iter()
        .map(|row| row.display_name)
        .collect();

    assert_eq!(first, 1);
    // ★ The tie-break is the identifier **ascending**, in both the delete and the listing — so among three heard at the
    // same moment the first two alphabetically are the ones kept. The first version of this assertion expected the last two,
    // which the store was right not to produce.
    assert_eq!(surviving, vec!["alpha".to_owned(), "bravo".to_owned()]);
}

#[test]
fn a_ceiling_of_zero_keeps_nothing_rather_than_everything() {
    // ★ The boundary that a "keep at most N" written as a comparison gets wrong. An empty `LIMIT 0` subquery means the
    // delete removes every row — which is what "keep zero" says — while a rule expressed as `last_seen_ms > cutoff` with no
    // rows to compare against would remove nothing at all and leave the table growing for ever.
    let db = migrated();
    db.record_seen_device(&heard("one", 1_000)).expect("heard");
    db.record_seen_device(&heard("two", 2_000)).expect("heard");

    assert_eq!(db.forget_seen_devices_beyond(0).expect("collected"), 2);
    assert!(db.seen_devices().expect("listed").is_empty());
}

#[test]
fn a_device_that_was_seen_again_counts_as_recent() {
    // The upsert moves `last_seen_ms` forward, so a device that has been around for months but was heard a moment ago is
    // the most recent thing in the table rather than the oldest.
    let db = migrated();
    let mut familiar = heard("familiar", 1_000);
    db.record_seen_device(&familiar).expect("heard");
    db.record_seen_device(&heard("passer-by", 2_000)).expect("heard");

    familiar.seen_at_ms = 9_000;
    db.record_seen_device(&familiar).expect("heard again");

    assert_eq!(db.forget_seen_devices_beyond(1).expect("collected"), 1);
    let left = db.seen_devices().expect("listed");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].display_name, "familiar", "the one that came back");
}

// ── 跨设备的插件状态 ────────────────────────────────────────────────────────────────────────────

#[test]
fn a_sync_record_round_trips() {
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.2.0", "sha256-abc", 2_000).expect("records");

    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].plugin_id, "@acme/chat");
    assert_eq!(rows[0].peer_device, "device-b");
    assert_eq!(rows[0].version, "1.2.0");
    assert_eq!(rows[0].digest, "sha256-abc");
    assert_eq!(rows[0].synced_at_ms, 2_000);
}

#[test]
fn a_second_round_for_the_same_peer_corrects_the_row_rather_than_adding_one() {
    // ★ 表的主键是 (plugin_id, peer_device)，而这是正确的形状：这张表回答「对端已经有了吗」，
    // 而一台设备两行会让这个问题有两个答案。同步的历史是 `plugin_sync::SyncRecord` 的事。
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.0.0", "sha256-old", 1_000).expect("first");
    db.record_sync("@acme/chat", "device-b", "1.1.0", "sha256-new", 2_000).expect("second");

    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 1, "a second round added a row: {rows:?}");
    assert_eq!(rows[0].version, "1.1.0");
    assert_eq!(rows[0].digest, "sha256-new");
    assert_eq!(rows[0].synced_at_ms, 2_000);

    // 而另一台设备是另一行，所以「谁已经有了」仍然是一台一行。
    db.record_sync("@acme/chat", "device-c", "1.1.0", "sha256-new", 2_500).expect("third");
    assert_eq!(db.sync_records().expect("reads").len(), 2);
}

#[test]
fn a_peer_that_was_asked_again_replaces_what_was_known() {
    // ★ 一次**活的答复**是完整的：它说的是「现在有哪些」，不是增量。一台设备卸载了一个插件之后，
    // 它的答复里就没有那一行 —— 而 upsert 看不见「没有」，旧行会留到永远，于是每次计划都认为对端还持有着它。
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.0.0", "sha256-old", 1_000).expect("first");
    db.record_sync("@acme/gone", "device-b", "1.0.0", "sha256-gone", 1_000).expect("second");
    // 另一台设备的话不受影响：这次问的是 device-b。
    db.record_sync("@acme/chat", "device-c", "1.0.0", "sha256-old", 1_000).expect("another peer");

    let held = [("@acme/chat".to_owned(), "1.1.0".to_owned(), "sha256-new".to_owned())];
    db.replace_sync_for_peer("device-b", &held, 2_000).expect("replaces");

    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 2, "one row for each peer: {rows:?}");
    let b = rows.iter().find(|row| row.peer_device == "device-b").expect("device-b");
    assert_eq!(b.version, "1.1.0");
    assert_eq!(b.digest, "sha256-new");
    assert_eq!(b.synced_at_ms, 2_000);
    assert!(
        rows.iter().all(|row| row.plugin_id != "@acme/gone"),
        "the plugin device-b no longer has is gone from the table: {rows:?}"
    );
    let c = rows.iter().find(|row| row.peer_device == "device-c").expect("device-c");
    assert_eq!(c.version, "1.0.0", "the other peer's answer is untouched");
}

#[test]
fn a_refused_replacement_leaves_the_old_answer_alone() {
    // ★ 删除与插入属于同一个事务：一次失败的插入如果只回滚自己，对端就会变成「什么都没有」——
    // 那是这张表能给出的、代价最大的错误答案。同一插件两行会撞主键，正好用来让第二次插入失败。
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.0.0", "sha256-old", 1_000).expect("first");
    let duplicated = [
        ("@acme/chat".to_owned(), "1.1.0".to_owned(), "sha256-new".to_owned()),
        ("@acme/chat".to_owned(), "1.2.0".to_owned(), "sha256-newer".to_owned()),
    ];

    let refused = db.replace_sync_for_peer("device-b", &duplicated, 2_000);

    assert!(refused.is_err(), "a duplicate primary key was accepted");
    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 1, "the delete was not rolled back: {rows:?}");
    assert_eq!(rows[0].version, "1.0.0", "the old answer survived");
}

// ── 同步的历史 ──────────────────────────────────────────────────────────────────────────────────

fn a_log_row(sync_id: &str, plugin: &str, started_at_ms: i64, finished: bool) -> SyncLogRow {
    SyncLogRow {
        sync_id: sync_id.to_owned(),
        plugin_id: plugin.to_owned(),
        peer_device: "device-b".to_owned(),
        started_at_ms,
        finished_at_ms: if finished { Some(started_at_ms + 500) } else { None },
        document: format!("{{\"syncId\":\"{sync_id}\"}}"),
    }
}

#[test]
fn a_round_is_recorded_and_read_back_newest_first() {
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, true)).expect("first");
    db.record_sync_log(&a_log_row("sync-2", "@acme/chat", 2_000, true)).expect("second");

    let rows = db.sync_log(None, 10).expect("reads");
    assert_eq!(rows.len(), 2, "{rows:?}");
    // 最新在前：历史页面看的是刚刚发生了什么，而不是最早发生了什么。
    assert_eq!(rows[0].sync_id, "sync-2");
    assert_eq!(rows[1].sync_id, "sync-1");
    assert_eq!(rows[0].document, "{\"syncId\":\"sync-2\"}");
    // 以及 `limit` 真的限制住。
    assert_eq!(db.sync_log(None, 1).expect("reads").len(), 1);
}

#[test]
fn a_round_that_is_still_running_has_no_finish_time() {
    // 可空列不能用 `required`：没有结束时间是**事实**，不是缺陷 —— 一轮同步在开始时先写一行。
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, false)).expect("started");

    let rows = db.sync_log(None, 10).expect("reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].finished_at_ms, None);
    assert!(rows[0].document.contains("sync-1"));
}

#[test]
fn finishing_a_round_corrects_its_row_rather_than_adding_one() {
    // ★ 一轮写两次：开始时一次、结束时一次 —— 而第二次是**同一轮**，不是第二轮。
    // 两行会让历史把一轮显示两遍，其中一遍说它从未结束。
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, false)).expect("started");
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, true)).expect("finished");

    let rows = db.sync_log(None, 10).expect("reads");
    assert_eq!(rows.len(), 1, "finishing added a row: {rows:?}");
    assert_eq!(rows[0].finished_at_ms, Some(1_500));
}

#[test]
fn the_history_can_be_asked_about_one_plugin() {
    // 这两个问题是历史页面真正要问的，所以它们是列；其余在 document 里，不必为查一次而解析每一行。
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, true)).expect("chat");
    db.record_sync_log(&a_log_row("sync-2", "@acme/notes", 2_000, true)).expect("notes");

    let chat = db.sync_log(Some("@acme/chat"), 10).expect("reads");
    assert_eq!(chat.len(), 1, "{chat:?}");
    assert_eq!(chat[0].plugin_id, "@acme/chat");
    assert_eq!(db.sync_log(None, 10).expect("reads").len(), 2);
}

#[test]
fn removing_a_plugin_takes_its_decisions_with_it() {
    // ★ Two deletes, one transaction. A grant recorded against a plugin that no longer exists is not history worth
    // keeping — plugin_grants is the current state — and the row left behind would let a reinstall inherit consent
    // nobody gave about the new package. The assertion is that both tables agree afterwards, not just the one.

    let mut db = migrated();
    let plugin = "@acme/removable";
    db.insert_plugin(plugin, true, true, "installed", 1, 1).expect("a row");
    db.record_grants(plugin, &[("log:*".to_owned(), true)], 2, "digest").expect("a decision");
    assert_eq!(db.plugin_grants(plugin).expect("decisions").len(), 1);

    assert!(db.remove_plugin(plugin).expect("removed"), "a row was there");

    assert!(!db.plugin_is_installed(plugin).expect("the table"), "no row");
    assert!(db.plugin_grants(plugin).expect("decisions").is_empty(), "and no decisions either");
    // A second removal answers honestly rather than claiming a success.
    assert!(!db.remove_plugin(plugin).expect("removed"), "nothing was there");
}

#[test]
fn an_action_is_replaced_rather_than_repeated() {
    // ★ A plugin declares its actions each time it activates. The second declaration of one name is the same action
    // with a possibly newer schema — an upsert. An insert would make the declaration path work once and fail on every
    // restart, which is the shape of a bug that only appears after a restart.
    let db = migrated();
    let plugin = "@acme/actionful";
    db.insert_plugin(plugin, true, true, "installed", 1, 1).expect("a row");

    db.record_plugin_action(plugin, "send", Some(r#"{"type":"object"}"#), Some("Send a message"))
        .expect("declared");
    db.record_plugin_action(plugin, "send", Some(r#"{"type":"object","required":["to"]}"#), None)
        .expect("declared again");

    let actions = db.plugin_actions(plugin).expect("actions");
    assert_eq!(actions.len(), 1, "a redeclaration added a row: {actions:?}");
    assert_eq!(actions[0].name, "send");
    assert_eq!(actions[0].args_schema.as_deref(), Some(r#"{"type":"object","required":["to"]}"#));
    // The new declaration said nothing about a description, so there is none: keeping the old sentence would attribute
    // it to a schema it never described.
    assert_eq!(actions[0].description, None);
}

#[test]
fn actions_are_ordered_and_scoped_to_their_plugin() {
    let db = migrated();
    for plugin in ["@acme/one", "@acme/two"] {
        db.insert_plugin(plugin, true, true, "installed", 1, 1).expect("a row");
    }
    db.record_plugin_action("@acme/one", "zeta", None, None).expect("zeta");
    db.record_plugin_action("@acme/one", "alpha", None, None).expect("alpha");
    db.record_plugin_action("@acme/two", "other", None, None).expect("other");

    let one: Vec<String> = db
        .plugin_actions("@acme/one")
        .expect("actions")
        .into_iter()
        .map(|action| action.name)
        .collect();
    assert_eq!(one, vec!["alpha".to_owned(), "zeta".to_owned()], "not sorted: {one:?}");
    assert_eq!(db.plugin_actions("@acme/two").expect("actions").len(), 1, "scoped by plugin");
}

#[test]
fn an_action_cannot_outlive_its_plugin() {
    // The foreign key is the enforcement, and it is the right one: a page's `self.invoke` checks the action belongs to
    // the plugin, so an action row for a plugin that is not installed would be a name that resolves to nothing.
    let db = migrated();

    let refused = db.record_plugin_action("@acme/absent", "send", None, None);

    assert!(refused.is_err(), "an action was recorded for a plugin nobody installed");
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
        .find(|migration| migration.version == 11)
        .expect("the clipboard migration");
    let db = SynraDb::open_in_memory().expect("opens");
    for earlier in MIGRATIONS.iter().filter(|migration| migration.version < 11) {
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
