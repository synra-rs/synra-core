use super::super::Absorbed;
use super::{OTHER, PEER, address, announcement, device, short_table, table};

#[test]
fn a_candidate_expires_after_its_lifetime() {
    let mut table = short_table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
    assert_eq!(table.current(500).count(), 1);
    assert_eq!(table.current(1_000).count(), 0, "the boundary is exclusive");
}

#[test]
fn a_paired_device_never_expires() {
    // ★ The pairing is recorded and the user approved it. A paired device that has gone quiet is one that is
    // *offline*, which the interface shows and the user can act on — dropping it would make the device vanish until
    // it was rediscovered, which reads as an unpairing.
    let mut table = short_table();
    table.paired(device(PEER), address(47100), Some("Phone"), 0);
    assert_eq!(table.current(1_000_000).count(), 1);
    // But it is still dropped by `forget`, because that is the user deciding.
    assert!(table.forget(device(PEER)).is_some());
}

#[test]
fn expiring_returns_what_it_dropped_so_a_screen_can_be_told() {
    // ★ A device that disappears from a list without an event is one a screen keeps showing. The candidates are
    // returned rather than only a count because the caller cannot look them up afterwards — they are gone.
    let mut table = short_table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
    table.absorb(&announcement(OTHER, "Tablet", 47100), address(0), 900);

    let expired = table.expire(1_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].device_id, device(PEER));
    assert_eq!(expired[0].display_name, "Phone");
    assert_eq!(table.len(), 1);
}

#[test]
fn a_goodbye_ages_the_entry_out_at_the_ordinary_rate() {
    // ★ A goodbye is the beginning of the end of the entry, not a refresh of it. Leaving the last-seen time alone
    // would keep the entry alive for a further lifetime after the device said it was leaving.
    let mut table = short_table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
    assert_eq!(
        table.went_offline(device(PEER), 100),
        Absorbed::Offline {
            device_id: device(PEER)
        }
    );
    // The entry was pushed a lifetime back, so it is already expired at the moment of the goodbye.
    assert_eq!(table.current(100).count(), 0);
}

#[test]
fn a_goodbye_from_an_unknown_device_says_so_rather_than_creating_one() {
    // A goodbye for a device we have never heard of is not a reason to start showing it.
    let mut table = table();
    assert_eq!(
        table.went_offline(device(OTHER), 1_000),
        Absorbed::Unchanged {
            device_id: device(OTHER)
        }
    );
    assert!(table.is_empty());
}

#[test]
fn forgetting_is_what_a_block_does_and_it_does_not_come_back_from_a_broadcast() {
    // The user decided, and a device that is blocked must not be shown again because it broadcast once more.
    let mut table = table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
    assert!(table.forget(device(PEER)).is_some());
    assert!(
        table.forget(device(PEER)).is_none(),
        "forgetting twice should say nothing was there"
    );
    assert!(table.is_empty());
}
