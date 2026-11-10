use super::migrated;

/// A sighting of a device the fixture names, at a moment it names.
///
/// The `discovery::sighting` fixture has a fixed identifier, which is right for the upsert tests and wrong for a retention one:
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
