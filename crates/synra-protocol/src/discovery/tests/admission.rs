use crate::handshake::PROTOCOL_VERSION;
use crate::ids::DeviceId;
use super::super::{
    Candidate, DeviceAnnouncement, Discovery, DiscoveryDatagram, DiscoveryError, DiscoveryQuery,
    MAX_ANNOUNCED_NAME, OfflineAnnouncement, TrustLevel, encode_query,
};
use super::{device, ip};

#[test]
fn an_announcement_from_another_protocol_version_is_refused() {
    let mut announcement = device(DeviceId::new(), 32100);
    announcement.protocol = 2;
    assert!(matches!(
        announcement.validate(),
        Err(DiscoveryError::VersionMismatch { ours: 1, theirs: 2 })
    ));
}

#[test]
fn an_announcement_missing_essentials_is_refused() {
    /// Mutates one field, so a table of negative cases can be one loop.
    type Mutate = fn(&mut DeviceAnnouncement);
    let cases: &[(&str, Mutate)] = &[
        ("nil device", |a| {
            a.device_id = DeviceId::from_uuid(uuid::Uuid::nil())
        }),
        ("port zero", |a| a.port = 0),
        ("blank name", |a| a.display_name = "   ".to_owned()),
        ("long name", |a| {
            a.display_name = "x".repeat(MAX_ANNOUNCED_NAME + 1)
        }),
    ];

    for (label, mutate) in cases {
        let mut announcement = device(DeviceId::new(), 32100);
        mutate(&mut announcement);
        assert!(
            announcement.validate().is_err(),
            "{label} should be refused"
        );
    }
}

#[test]
fn optional_announcement_fields_may_be_absent() {
    // A bare query from a device that has not yet worked out its own platform is still useful:
    // the responder only needs an address and a port to reply.
    let announcement = DeviceAnnouncement {
        device_id: DeviceId::new(),
        display_name: "phone".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: 32100,
        platform: None,
        app_version: None,
        features: Vec::new(),
    };
    assert_eq!(announcement.validate(), Ok(()));

    let bytes = encode_query(&announcement).expect("encodes");
    let text = String::from_utf8(bytes).expect("utf8");
    for absent in ["platform", "app_version", "features"] {
        assert!(!text.contains(absent), "{absent} should be omitted: {text}");
    }
}

#[test]
fn a_device_never_admits_its_own_datagrams() {
    let local = DeviceId::new();
    let discovery = Discovery::new(local, vec![ip(5), ip(9)]);

    // By device id.
    let own = DiscoveryDatagram::Query(DiscoveryQuery {
        device: device(local, 32100),
    });
    assert!(!discovery.admit(&own, ip(50)), "this is us");

    // By source address, which catches a device that has not learned its own id yet, or one
    // whose advertised id differs from the interface the datagram left by.
    let other = DiscoveryDatagram::Query(DiscoveryQuery {
        device: device(DeviceId::new(), 32100),
    });
    assert!(
        !discovery.admit(&other, ip(5)),
        "that is one of our own addresses"
    );

    // Somebody else.
    assert!(discovery.admit(&other, ip(50)));
}

#[test]
fn the_self_check_is_the_only_one() {
    // The check has to be complete on its own: a caller that also filtered elsewhere would be
    // relying on a second layer, and the point of one place is that no such layer exists.
    let local = DeviceId::new();
    let discovery = Discovery::new(local, vec![ip(5)]);
    assert_eq!(discovery.local_id(), local);
    assert_eq!(discovery.local_addresses(), &[ip(5)]);

    // A datagram from ourselves is refused regardless of the source address.
    let own = DiscoveryDatagram::Offline(OfflineAnnouncement {
        device_id: local,
        timestamp: 0,
    });
    assert!(!discovery.admit(&own, ip(200)));
}

#[test]
fn discovery_alone_can_never_make_a_device_displayable() {
    // The rule that keeps a spoofed datagram out of the interface: a candidate from UDP is a
    // hint, and only a completed handshake turns it into a peer.
    let candidate = Candidate {
        device: device(DeviceId::new(), 32100),
        source: ip(50),
        trust: TrustLevel::Announced,
    };
    assert!(
        !candidate.is_displayable(),
        "an announcement is not an identity"
    );

    let promoted = Discovery::handshaked(candidate.clone());
    assert!(promoted.is_displayable());
    assert_eq!(
        promoted.device, candidate.device,
        "promotion changes only the trust"
    );
    assert_eq!(promoted.endpoint(), (ip(50), 32100));

    assert!(TrustLevel::Handshaked < TrustLevel::Paired);
    assert!(!TrustLevel::Announced.is_displayable());
    assert!(TrustLevel::Paired.is_displayable());
}
