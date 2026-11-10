use std::net::{Ipv4Addr, SocketAddr};
use synra_protocol::discovery::{DeviceAnnouncement, TrustLevel};
use synra_protocol::handshake::PROTOCOL_VERSION;
use synra_protocol::session::PlatformKind;
use crate::discovery::{Absorbed, DiscoveryTable};
use super::{A, B, device, host};

#[test]
fn a_new_host_knows_itself_and_nobody_else() {
    let (host, _db) = host(A, "Laptop");
    assert_eq!(host.device_id(), device(A));
    assert_eq!(host.identity().display_name, "Laptop");
    assert!(host.discovery().is_empty());
    assert!(host.sessions().is_empty());
    assert!(host.listener.is_none());
    assert_eq!(host.sent(), 0);
}

#[test]
fn listening_reports_the_port_the_operating_system_chose() {
    // The port is read back rather than assumed: a caller that passed zero asked for any port, and the value it
    // needs is the one that was granted.
    let (mut host, _db) = host(A, "Laptop");
    let bound = host
        .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binds");
    assert_ne!(bound.port(), 0);
    assert!(host.listener.is_some());
}

#[test]
fn an_announcement_heard_over_the_network_becomes_a_candidate() {
    let (mut host, _db) = host(A, "Laptop");
    let announcement = DeviceAnnouncement {
        device_id: device(B),
        display_name: "Phone".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: 47100,
        platform: Some(PlatformKind::Android),
        app_version: Some("0.1.0".to_owned()),
        features: Vec::new(),
    };
    let result = host.heard(
        &announcement,
        SocketAddr::from(([10, 0, 0, 5], 5_4321)),
        1_000,
    );
    assert_eq!(
        result,
        Absorbed::New {
            device_id: device(B)
        }
    );
    let candidate = host.discovery().get(device(B)).expect("a candidate");
    assert_eq!(candidate.trust, TrustLevel::Announced);
    assert_eq!(candidate.address.port(), 47100);
    // And it is not yet something the interface offers, because an announcement is a hint and not evidence.
    assert!(host.usable(1_000).is_empty());
}

#[test]
fn a_host_expires_candidates_and_reports_what_went() {
    let (mut host, _db) = host(A, "Laptop");
    let announcement = DeviceAnnouncement {
        device_id: device(B),
        display_name: "Phone".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: 47100,
        platform: None,
        app_version: None,
        features: Vec::new(),
    };
    host.heard(&announcement, SocketAddr::from(([10, 0, 0, 5], 1)), 0);

    // The default lifetime is 90 seconds, so an hour later it is long gone.
    let expired = host.expire(3_600_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].device_id, device(B));
    assert!(host.discovery().is_empty());
}

#[test]
fn a_table_with_a_chosen_lifetime_is_what_a_test_needs() {
    // The discovery table's lifetime is a value rather than a constant, which is what lets the expiry tests above
    // run without waiting ninety seconds.
    let table = DiscoveryTable::with_ttl(device(A), std::time::Duration::from_millis(10));
    assert_eq!(table.ttl(), std::time::Duration::from_millis(10));
}
