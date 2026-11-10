use synra_protocol::handshake::{Feature, PROTOCOL_VERSION, SessionNonce};
use synra_protocol::session::PlatformKind;
use super::super::{LocalPeer, agree};
use super::{ACCEPTOR, device, peer};

#[test]
fn features_in_common_are_the_intersection() {
    let ours = LocalPeer {
        features: vec![Feature::EventStream, Feature::ClipboardSync],
        requires: Vec::new(),
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[]);
    assert_eq!(agreed.common, vec![Feature::EventStream]);
    assert!(agreed.is_usable());
}

#[test]
fn a_required_feature_the_peer_lacks_is_reported() {
    // Our own requirement.
    let ours = LocalPeer {
        requires: vec![Feature::TransferResume],
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[], &[]);
    assert_eq!(agreed.missing_required, vec![Feature::TransferResume]);
    assert!(!agreed.is_usable());
}

#[test]
fn a_required_feature_the_peer_needs_and_we_lack_is_reported_too() {
    // ★ Both directions. A link where the peer requires something we lack is as unusable as the reverse — and a
    // check that looked only at our own list would let us start work the peer will refuse.
    let ours = LocalPeer {
        features: vec![Feature::EventStream],
        requires: Vec::new(),
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[Feature::PluginMirroring]);
    assert_eq!(agreed.missing_required, vec![Feature::PluginMirroring]);
    assert!(!agreed.is_usable());
}

#[test]
fn a_requirement_both_sides_meet_is_not_missing() {
    let ours = LocalPeer {
        features: vec![Feature::EventStream],
        requires: vec![Feature::EventStream],
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[Feature::EventStream]);
    assert!(agreed.missing_required.is_empty());
    assert!(agreed.is_usable());
}

#[test]
fn a_requirement_is_reported_once_even_when_both_sides_name_it() {
    // Two entries for one feature would make a report say a link is missing two things when it is missing one.
    let ours = LocalPeer {
        features: vec![Feature::EventStream],
        requires: vec![Feature::PluginMirroring],
        ..peer(ACCEPTOR, "L", PlatformKind::Desktop)
    };
    let agreed = agree(&ours, &[Feature::EventStream], &[Feature::PluginMirroring]);
    assert_eq!(agreed.missing_required, vec![Feature::PluginMirroring]);
}

#[test]
fn an_announcement_carries_the_port_it_was_given() {
    // ★ The port is the **connection** port, and this type does not hold it. A `LocalPeer` that guessed would
    // announce a port nothing is listening on — a device that appears in every list and cannot be connected to.
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let announcement = ours.announcement(47_100);
    assert_eq!(announcement.port, 47_100);
    assert_eq!(announcement.device_id, device(ACCEPTOR));
    assert_eq!(announcement.display_name, "Laptop");
    assert_eq!(announcement.platform, Some(PlatformKind::Desktop));
    assert_eq!(announcement.protocol, PROTOCOL_VERSION);
}

#[test]
fn an_announcement_passes_the_protocols_own_validation() {
    // The announcement is encoded and broadcast, and the receiving end validates it. One this build produces that
    // its own parser refuses would be a device that can never be found.
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    assert!(ours.announcement(47_100).validate().is_ok());
}

#[test]
fn the_default_features_are_the_protocols_own_catalogue() {
    // ★ A build that forgot to announce a feature it implements would be one whose peers decline to use it, and
    // nothing would say why. Asserted against the catalogue so the two cannot drift.
    assert_eq!(LocalPeer::default_features(), Feature::ALL.to_vec());
    assert!(!LocalPeer::default_features().is_empty());
}

#[test]
fn a_local_peer_builds_a_hello_and_an_ack_that_agree_with_each_other() {
    // The two messages carry the same facts, so a field set in one and not the other is a peer that looks different
    // depending on which end dialled.
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let nonce = SessionNonce::random();
    let hello = ours.hello(nonce, 3);
    let ack = ours.hello_ack(nonce, 3);

    assert_eq!(hello.device_id, ack.device_id);
    assert_eq!(hello.display_name, ack.display_name);
    assert_eq!(hello.platform, ack.platform);
    assert_eq!(hello.app_version, ack.app_version);
    assert_eq!(hello.protocol, ack.protocol);
    assert_eq!(hello.nonce, ack.nonce);
    assert_eq!(hello.sequence, ack.sequence);
    assert_eq!(hello.features, ack.features);
}
