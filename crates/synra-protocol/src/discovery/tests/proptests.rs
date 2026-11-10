use super::super::{DeviceAnnouncement, Discovery, DiscoveryDatagram, DiscoveryQuery, encode_query};

use core::net::{IpAddr, Ipv4Addr};

use crate::handshake::{Feature, PROTOCOL_VERSION};
use crate::ids::DeviceId;
use crate::session::PlatformKind;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(
            concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/discovery.txt"),
        ))),
        ..ProptestConfig::default()
    })]

    /// Any datagram that encodes parses back to itself. Discovery drives connection attempts, so
    /// a field lost or altered in round-tripping is a device reached at the wrong address.
    #[test]
    fn announcements_round_trip(
        port in 1u16..=u16::MAX,
        // Starts with an alphanumeric, so the name is never blank. A generator that could produce
        // all-whitespace would fail on `validate`, which is a different property's business.
        name in "[A-Za-z0-9][A-Za-z0-9 ]{0,39}",
        platform in proptest::option::of(Just(PlatformKind::Desktop)),
    ) {
        let announcement = DeviceAnnouncement {
            device_id: DeviceId::new(),
            display_name: name,
            protocol: PROTOCOL_VERSION,
            port,
            platform,
            app_version: None,
            features: vec![Feature::EventStream],
        };

        let bytes = encode_query(&announcement).expect("encodes");
        match DiscoveryDatagram::parse(&bytes).expect("parses") {
            DiscoveryDatagram::Query(query) => prop_assert_eq!(query.device, announcement),
            other => prop_assert!(false, "expected a query, got {:?}", other),
        }
    }

    /// Arbitrary bytes either parse or are refused with a reason. Discovery runs on an open UDP
    /// port, so an attacker controls this input completely and it must never panic.
    #[test]
    fn arbitrary_datagrams_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = DiscoveryDatagram::parse(&bytes);
    }

    /// A device's own datagrams are never admitted, whichever way it is identified.
    #[test]
    fn self_datagrams_are_never_admitted(last_octet in 1u8..=254, other in 1u8..=254) {
        let local = DeviceId::new();
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet));
        let discovery = Discovery::new(local, vec![local_ip]);

        // By id.
        let by_id = DiscoveryDatagram::Query(DiscoveryQuery {
            device: DeviceAnnouncement {
                device_id: local,
                display_name: "self".to_owned(),
                protocol: PROTOCOL_VERSION,
                port: 32100,
                platform: None,
                app_version: None,
                features: Vec::new(),
            },
        });
        prop_assert!(!discovery.admit(&by_id, IpAddr::V4(Ipv4Addr::new(10, 0, 0, other))));

        // By address, even with an id we have never seen.
        let by_address = DiscoveryDatagram::Query(DiscoveryQuery {
            device: DeviceAnnouncement {
                device_id: DeviceId::new(),
                display_name: "stranger".to_owned(),
                protocol: PROTOCOL_VERSION,
                port: 32100,
                platform: None,
                app_version: None,
                features: Vec::new(),
            },
        });
        prop_assert!(!discovery.admit(&by_address, local_ip));
    }
}
