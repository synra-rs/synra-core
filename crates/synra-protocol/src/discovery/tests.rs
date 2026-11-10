use super::*;
use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;

use crate::handshake::{Feature, PROTOCOL_VERSION};
use crate::ids::DeviceId;
use crate::limits;
use crate::session::PlatformKind;

fn device(id: DeviceId, port: u16) -> DeviceAnnouncement {
    DeviceAnnouncement {
        device_id: id,
        display_name: "laptop".to_owned(),
        protocol: PROTOCOL_VERSION,
        port,
        platform: Some(PlatformKind::Desktop),
        app_version: Some("1.0.0".to_owned()),
        features: vec![Feature::EventStream, Feature::LanDiscovery],
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

#[test]
fn a_query_round_trips() {
    let original = device(DeviceId::new(), 32100);
    let bytes = encode_query(&original).expect("encodes");

    // The magic, a separator, then JSON.
    let text = String::from_utf8(bytes.clone()).expect("utf8");
    assert!(text.starts_with(QUERY_MAGIC), "{text}");
    assert_eq!(text.chars().nth(QUERY_MAGIC.len()), Some(MAGIC_SEPARATOR));

    match DiscoveryDatagram::parse(&bytes).expect("parses") {
        DiscoveryDatagram::Query(query) => assert_eq!(query.device, original),
        other => panic!("expected a query, got {other:?}"),
    }
}

#[test]
fn a_response_round_trips_with_no_marker() {
    let original = device(DeviceId::new(), 32100);
    let bytes = encode_response(&original).expect("encodes");

    // No magic: a response is a unicast reply, so there is nothing to disambiguate it from.
    let text = String::from_utf8(bytes.clone()).expect("utf8");
    assert!(!text.contains(QUERY_MAGIC));

    match DiscoveryDatagram::parse(&bytes).expect("parses") {
        DiscoveryDatagram::Response(response) => assert_eq!(response.device, original),
        other => panic!("expected a response, got {other:?}"),
    }
}

#[test]
fn an_offline_announcement_round_trips() {
    let original = OfflineAnnouncement {
        device_id: DeviceId::new(),
        timestamp: 1_700_000_000_000,
    };
    let bytes = encode_offline(&original).expect("encodes");

    let text = String::from_utf8(bytes.clone()).expect("utf8");
    assert!(text.starts_with(OFFLINE_MAGIC), "{text}");

    match DiscoveryDatagram::parse(&bytes).expect("parses") {
        DiscoveryDatagram::Offline(offline) => assert_eq!(offline, original),
        other => panic!("expected an offline announcement, got {other:?}"),
    }
}

#[test]
fn unknown_fields_in_a_discovery_datagram_are_ignored() {
    // The opposite of the envelope rule, and deliberately so: broadcast reaches devices running
    // versions we have never seen, and refusing an unfamiliar field means a device silently fails
    // to be discoverable at all.
    let body = format!(
        r#"{{"device_id":"{}","display_name":"phone","protocol":1,"port":32100,"somethingNew":true}}"#,
        DeviceId::new(),
    );
    let datagram = format!("{QUERY_MAGIC}\n{body}");
    match DiscoveryDatagram::parse(datagram.as_bytes()).expect("parses") {
        DiscoveryDatagram::Query(query) => assert_eq!(query.device.display_name, "phone"),
        other => panic!("expected a query, got {other:?}"),
    }
}

#[test]
fn a_datagram_with_no_separator_is_not_a_query() {
    // Without the separator, `SYNRA_DISCOVERY{...}` would be neither a query nor valid JSON, and
    // reporting it as an unknown datagram is clearer than reporting a JSON error.
    let text = format!("{QUERY_MAGIC}{{\"device_id\":\"x\"}}");
    assert!(matches!(
        DiscoveryDatagram::parse(text.as_bytes()),
        Err(DiscoveryError::UnknownKind)
    ));
}

#[test]
fn unparseable_datagrams_are_refused() {
    assert!(matches!(
        DiscoveryDatagram::parse(b"random noise"),
        Err(DiscoveryError::UnknownKind)
    ));
    assert!(matches!(
        DiscoveryDatagram::parse(b"SYNRA_DISCOVERY\n{not json}"),
        Err(DiscoveryError::Malformed { kind: "query", .. })
    ));
    assert!(matches!(
        DiscoveryDatagram::parse(b"SYNRA_OFFLINE\n{not json}"),
        Err(DiscoveryError::Malformed {
            kind: "offline",
            ..
        })
    ));
    // Invalid UTF-8 cannot be JSON either.
    assert!(matches!(
        DiscoveryDatagram::parse(&[0xFF, 0xFE]),
        Err(DiscoveryError::NotUtf8)
    ));
}

#[test]
fn an_oversized_datagram_is_refused_before_parsing() {
    // The port is open by design, so the ceiling is what stops a flood from exhausting a receive
    // buffer.
    let mut bytes = vec![b'x'; MAX_DATAGRAM_LEN + 1];
    match DiscoveryDatagram::parse(&bytes) {
        Err(DiscoveryError::TooLarge { len, max }) => {
            assert_eq!(len, MAX_DATAGRAM_LEN + 1);
            assert_eq!(max, MAX_DATAGRAM_LEN);
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }

    // Exactly at the ceiling is allowed through to the parser.
    bytes.truncate(MAX_DATAGRAM_LEN);
    assert!(matches!(
        DiscoveryDatagram::parse(&bytes),
        Err(DiscoveryError::UnknownKind)
    ));
}

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

#[test]
fn the_default_scan_budget_is_self_consistent() {
    assert_eq!(ScanBudget::default().validate(), Ok(()));
}

#[test]
fn the_default_scan_budget_reads_its_numbers_from_the_limits() {
    // One source per number. A per-platform timeout is how "the same code behaves differently on
    // each device" starts.
    let budget = ScanBudget::default();
    assert_eq!(budget.total, limits::SCAN_TOTAL);
    assert_eq!(budget.passive, limits::SCAN_PASSIVE);
    assert_eq!(budget.probe_timeout, limits::SCAN_PROBE_TIMEOUT);
    assert_eq!(budget.probe_concurrency, limits::SCAN_PROBE_CONCURRENCY);
    assert_eq!(budget.query_interval(), limits::DISCOVERY_QUERY_INTERVAL);
    assert_eq!(budget.query_repeats(), limits::DISCOVERY_QUERY_REPEATS);
}

#[test]
fn a_degenerate_scan_budget_is_refused() {
    for budget in [
        ScanBudget {
            total: Duration::ZERO,
            ..ScanBudget::default()
        },
        ScanBudget {
            passive: Duration::ZERO,
            ..ScanBudget::default()
        },
        ScanBudget {
            probe_timeout: Duration::ZERO,
            ..ScanBudget::default()
        },
        ScanBudget {
            probe_concurrency: 0,
            ..ScanBudget::default()
        },
    ] {
        assert!(budget.validate().is_err());
    }

    // A passive window longer than the whole budget means the probe phase never runs, so
    // candidates are found and never checked.
    let passive_too_long = ScanBudget {
        passive: Duration::from_secs(60),
        total: Duration::from_secs(10),
        ..ScanBudget::default()
    };
    assert!(passive_too_long.validate().is_err());
}

#[test]
fn repeated_queries_must_fit_inside_the_passive_window() {
    // Otherwise a query is still going out after replies stopped being collected, and its answer
    // arrives with nobody listening.
    let too_short = ScanBudget {
        passive: Duration::from_millis(10),
        total: Duration::from_secs(10),
        ..ScanBudget::default()
    };
    assert!(too_short.validate().is_err());

    let default = ScanBudget::default();
    assert!(
        default.query_window() <= default.passive,
        "the default must satisfy its own rule"
    );
}

#[test]
fn the_probe_window_is_what_is_left_after_listening() {
    let budget = ScanBudget::default();
    assert_eq!(budget.probe_window(), budget.total - budget.passive);
}

#[test]
fn a_budget_can_say_whether_it_can_finish_a_probe_set() {
    let budget = ScanBudget {
        total: Duration::from_secs(2),
        passive: Duration::from_millis(500),
        probe_timeout: Duration::from_millis(200),
        probe_concurrency: 10,
    };
    // 1500ms of probe window, 200ms per batch of 10.
    assert!(budget.can_probe(0));
    assert!(budget.can_probe(10));
    assert!(budget.can_probe(70), "7 batches is 1400ms");
    assert!(
        !budget.can_probe(80),
        "8 batches is 1600ms, past the window"
    );
}

#[test]
fn an_offline_announcement_needs_a_device() {
    let good = OfflineAnnouncement {
        device_id: DeviceId::new(),
        timestamp: 0,
    };
    assert_eq!(good.validate(), Ok(()));

    let nil = OfflineAnnouncement {
        device_id: DeviceId::from_uuid(uuid::Uuid::nil()),
        timestamp: 0,
    };
    assert!(nil.validate().is_err());
}

#[test]
fn offline_announcements_are_best_effort() {
    // This runs while the process is shutting down, so it is bounded and short. More repeats
    // would delay shutdown for a message that is only an optimisation: a device that dies without
    // announcing itself is noticed anyway, via the heartbeat timeout.
    assert_eq!(offline_repeats(), limits::OFFLINE_ANNOUNCE_REPEATS);
    assert_eq!(offline_interval(), limits::OFFLINE_ANNOUNCE_INTERVAL);
    assert!(offline_repeats() <= 5, "shutdown must not be held up");
    let worst_case = offline_interval().saturating_mul(u32::from(offline_repeats()));
    assert!(worst_case < Duration::from_secs(1));
}

#[test]
fn a_datagram_reports_the_device_it_concerns() {
    let id = DeviceId::new();
    let query = DiscoveryDatagram::Query(DiscoveryQuery {
        device: device(id, 32100),
    });
    assert_eq!(query.device_id(), id);
    assert!(query.is_recognised());

    let offline = DiscoveryDatagram::Offline(OfflineAnnouncement {
        device_id: id,
        timestamp: 0,
    });
    assert_eq!(offline.device_id(), id);
}

#[test]
fn an_announcement_displays_readably_for_logs() {
    let announcement = device(DeviceId::new(), 32100);
    let text = announcement.to_string();
    assert!(text.contains("laptop"));
    assert!(text.contains("32100"));
}

#[cfg(test)]
mod proptests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr};

    use crate::handshake::{Feature, PROTOCOL_VERSION};
    use crate::ids::DeviceId;
    use crate::session::PlatformKind;
    use proptest::prelude::*;

    proptest! {
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
}
