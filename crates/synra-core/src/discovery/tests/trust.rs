use synra_protocol::discovery::TrustLevel;
use super::super::UNUSABLE_NAME;
use super::{PEER, address, announcement, device, table};

#[test]
fn a_handshake_raises_the_trust_level() {
    let mut table = table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
    assert!(table.handshaked(device(PEER), address(47100), Some("Phone"), 2_000));
    assert_eq!(
        table.get(device(PEER)).expect("c").trust,
        TrustLevel::Handshaked
    );
}

#[test]
fn an_announcement_cannot_demote_a_paired_device() {
    // ★ An announcement is unauthenticated, so it is not evidence that a pairing ended. A table that reset the level
    // would make a paired device fall back to "found on this network" every time it broadcast — and the user would
    // watch a device they had approved become unapproved, once every interval.
    let mut table = table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
    table.paired(device(PEER), address(47100), Some("Phone"), 1_500);
    assert_eq!(
        table.get(device(PEER)).expect("c").trust,
        TrustLevel::Paired
    );

    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 2_000);
    assert_eq!(
        table.get(device(PEER)).expect("c").trust,
        TrustLevel::Paired
    );
}

#[test]
fn a_handshake_over_a_different_address_records_where_it_actually_worked() {
    // ★ A handshake that completed proves the address the connection was made to works, which is better evidence
    // than anything a datagram claimed. Recording it is what makes the next connection attempt succeed.
    let mut table = table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
    table.handshaked(device(PEER), address(9_999), Some("Phone"), 2_000);
    assert_eq!(table.get(device(PEER)).expect("c").address.port(), 9_999);
}

#[test]
fn a_handshake_with_an_unknown_device_creates_a_candidate() {
    // A direct connection may be attempted without discovery, and refusing it would make discovery mandatory for a
    // device that is already known by address.
    let mut table = table();
    let known = table.handshaked(device(PEER), address(47100), Some("Phone"), 1_000);
    assert!(!known, "the device was not known before");
    let candidate = table.get(device(PEER)).expect("a candidate");
    assert_eq!(candidate.trust, TrustLevel::Handshaked);
    assert_eq!(candidate.display_name, "Phone");
    // And its claimed features are empty, because nothing claimed them — the connection proved identity, not ability.
    assert!(candidate.claimed_features.is_empty());
}

#[test]
fn a_handshake_with_a_bad_name_still_records_the_device() {
    let mut table = table();
    table.handshaked(device(PEER), address(47100), Some("bad\nname"), 1_000);
    assert_eq!(
        table.get(device(PEER)).expect("c").display_name,
        UNUSABLE_NAME
    );
}

#[test]
fn pairing_creates_a_candidate_when_discovery_never_saw_it() {
    // ★ A pairing can be made without discovery — two devices given each other's addresses. A table that required an
    // announcement first would make a paired device invisible until it happened to broadcast.
    let mut table = table();
    table.paired(device(PEER), address(47100), Some("Phone"), 1_000);
    let candidate = table.get(device(PEER)).expect("a candidate");
    assert_eq!(candidate.trust, TrustLevel::Paired);
    assert_eq!(candidate.address.port(), 47100);
}

#[test]
fn pairing_raises_the_level_on_a_device_already_known() {
    let mut table = table();
    table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
    table.paired(device(PEER), address(47100), Some("Approved"), 2_000);
    let candidate = table.get(device(PEER)).expect("c");
    assert_eq!(candidate.trust, TrustLevel::Paired);
    assert_eq!(candidate.display_name, "Approved");
}
