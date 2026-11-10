use core::time::Duration;
use crate::ids::DeviceId;
use crate::limits;
use super::super::{
    DiscoveryDatagram, DiscoveryError, DiscoveryQuery, MAGIC_SEPARATOR, MAX_DATAGRAM_LEN,
    OFFLINE_MAGIC, OfflineAnnouncement, QUERY_MAGIC, encode_offline, encode_query, encode_response,
    offline_interval, offline_repeats,
};
use super::device;

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
