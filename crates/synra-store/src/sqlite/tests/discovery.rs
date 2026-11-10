use super::migrated;

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
        address: None,
        paired_at_ms: 400,
    })
    .expect("pairs");
    db.record_seen_device(&sighting("Study PC", 500)).expect("records a sighting");

    assert_eq!(db.paired_devices().expect("reads").len(), 1, "still paired");
    assert_eq!(db.seen_devices().expect("reads").len(), 1, "and still heard from");
}
