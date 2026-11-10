use bytes::Bytes;
use serde_json::value::RawValue;
use crate::event::{EventName, events};
use crate::ids::{RequestId, TraceId};
use crate::error::ErrorCode;
use super::super::{Envelope, EnvelopeError, envelope_error_to_synra, parse_envelope};
use super::{device, spec};

#[test]
fn unknown_fields_are_rejected() {
    let local = device();
    let text = format!(
        r#"{{"requestId":"{}","event":"device.ping","target":"{local}","from":"{}","traceId":"{}","sentAtMs":1,"extraField":1}}"#,
        RequestId::new(),
        device(),
        TraceId::new().to_hex(),
    );
    let raw = RawValue::from_string(text).expect("valid json");
    // Accepting an extra field would let two implementations disagree about what a valid message
    // is, and the disagreement would surface as a mysterious failure much later.
    assert!(Envelope::inbound(&raw, local).is_err());
}

#[test]
fn wire_field_names_are_camel_case() {
    let (a, b) = (device(), device());
    let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    let json = serde_json::to_string(&envelope).expect("serialises");

    for name in ["requestId", "traceId", "sentAtMs"] {
        assert!(json.contains(&format!("\"{name}\"")), "{name} missing from {json}");
    }
    for absent in ["request_id", "trace_id", "sent_at_ms"] {
        assert!(!json.contains(absent), "{absent} leaked into {json}");
    }
    // Optional fields are absent rather than null, so a reader never has to handle both.
    for absent in ["replyTo", "ttlMs", "payload"] {
        assert!(!json.contains(absent), "{absent} should be omitted, not null: {json}");
    }
}

#[test]
fn built_in_events_are_accepted_and_nonsense_is_not() {
    let (a, b) = (device(), device());
    assert!(Envelope::outbound(spec(events::BYE, a, b), None::<&()>).is_ok());

    // `spec` asserts the name parses, so the negative cases check the parser directly.
    assert!(
        EventName::parse("nonsense").is_err(),
        "a bare word is in no known namespace",
    );
    assert!(
        EventName::parse("other.thing").is_err(),
        "an unknown namespace is not an event name",
    );

    // But a *valid* name this version does not define parses. That is deliberate: a newer peer
    // may send an event we have never heard of, and the inbound dispatcher records and ignores
    // it rather than closing the link. Parsing is a grammar check, not a catalogue lookup.
    assert!(EventName::parse("device.something-new").is_ok());
    assert!(EventName::parse("file.transfer.chunk").is_ok());
}

#[test]
fn envelope_errors_map_to_stable_codes() {
    let too_large = EnvelopeError::PayloadTooLarge { len: 1, max: 0 };
    assert_eq!(envelope_error_to_synra(&too_large).code, ErrorCode::PayloadTooLarge);

    let wrong_device = EnvelopeError::NotForUs { target: device(), local: device() };
    assert_eq!(envelope_error_to_synra(&wrong_device).code, ErrorCode::ProtocolViolation);

    let missing = EnvelopeError::MissingField { field: "event" };
    assert_eq!(envelope_error_to_synra(&missing).code, ErrorCode::InvalidArgument);
}

#[test]
fn parse_from_bytes_matches_parse_from_text() {
    let (a, b) = (device(), device());
    let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    let bytes = Bytes::from(serde_json::to_vec(&envelope).expect("serialises"));

    assert_eq!(parse_envelope(&bytes, b).expect("parses"), envelope);
}

#[test]
fn invalid_utf8_is_refused() {
    let bytes = Bytes::from_static(&[0xFF, 0xFE, 0x00]);
    assert!(matches!(
        parse_envelope(&bytes, device()),
        Err(EnvelopeError::NotUtf8)
    ));
}

#[test]
fn an_envelope_renders_readably_for_logs() {
    let (a, b) = (device(), device());
    let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    let text = envelope.to_string();
    assert!(text.contains("device.ping"));
    assert!(text.contains(&a.to_string()));
    assert!(text.contains(&b.to_string()));
}
