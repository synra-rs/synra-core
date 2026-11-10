use rusqlite::params;
use super::migrated;

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
