use std::net::IpAddr;
use synra_protocol::ids::DeviceId;
use super::super::{CANDIDATE_TTL, announced_address};
use super::{LOCAL, OTHER, PEER, address, announcement, device, short_table, table};

#[test]
fn the_current_list_excludes_the_expired_and_the_displayable_list_excludes_the_rest() {
    let mut table = short_table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
    table.absorb(&announcement(OTHER, "Tablet", 47100), address(0), 1_500);

    // At 1_900 the first is 1_900 old and expired, the second is 400 old and current — so one is current.
    assert_eq!(table.current(1_900).count(), 1);
    // ★ And the current one is **not** displayable: the protocol's own rule is `Handshaked | Paired`, so a device
    // heard from over UDP — which is unauthenticated — is a *candidate* and not a peer. The interface shows
    // candidates under a separate heading for exactly this reason.
    assert_eq!(
        table.displayable(1_900).count(),
        0,
        "an announced device is not displayable"
    );

    // A handshake is what makes it displayable, because a completed connection is evidence — and it does not change
    // whether the entry is current.
    table.handshaked(device(OTHER), address(47100), Some("Tablet"), 1_800);
    assert_eq!(table.displayable(1_900).count(), 1);
    assert_eq!(table.current(1_900).count(), 1);

    // Both are still in the table, because expiry is a separate act — a caller decides when to sweep.
    assert_eq!(table.iter().count(), 2);
    // At 3_100 the handshaked device is 1_300 old, so nothing is current any more. The arithmetic matters: the
    // `1_800` above is the handshake's own timestamp, and a test that reused `1_500` would leave the entry alive
    // for a further lifetime and assert the wrong thing about the sweep.
    assert_eq!(table.current(3_100).count(), 0);
    assert_eq!(table.expire(3_100).len(), 2);
    assert!(table.is_empty());
}

#[test]
fn the_list_is_in_identifier_order_so_two_runs_agree() {
    // Two renders of the same state have to agree, or a diff of two reports is noise.
    let mut table = table();
    table.absorb(&announcement(OTHER, "Z", 47100), address(0), 1_000);
    table.absorb(&announcement(PEER, "A", 47100), address(0), 1_000);

    let order: Vec<DeviceId> = table.iter().map(|candidate| candidate.device_id).collect();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(order, sorted);
}

#[test]
fn an_empty_table_reports_itself_as_empty() {
    let table = table();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
    assert_eq!(table.current(0).count(), 0);
    assert_eq!(table.displayable(0).count(), 0);
    assert!(table.get(device(PEER)).is_none());
    assert_eq!(table.local(), device(LOCAL));
    assert_eq!(table.ttl(), CANDIDATE_TTL);
}

#[test]
fn the_announced_address_uses_the_source_and_the_announced_port() {
    // Two different things, and mixing them is the bug the function exists to prevent.
    let ann = announcement(PEER, "Phone", 47100);
    let resolved = announced_address(IpAddr::from([192, 168, 1, 9]), &ann);
    assert_eq!(resolved.port(), 47100);
    assert_eq!(resolved.ip(), IpAddr::from([192, 168, 1, 9]));
}
