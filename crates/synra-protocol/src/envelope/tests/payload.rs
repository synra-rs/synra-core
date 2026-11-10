use serde_json::json;
use crate::limits::{MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_LEN};
use super::super::{Envelope, EnvelopeError};
use super::{device, round_trip, spec};

#[test]
fn a_payload_survives_as_its_original_text() {
    let (a, b) = (device(), device());
    let payload = json!({ "body": "hi", "n": 3 });
    let envelope =
        Envelope::outbound(spec("device.ping", a, b), Some(&payload)).expect("builds");

    let text = envelope.payload_str().expect("has a payload");
    // Not a re-serialised tree: the consumer parses exactly once.
    assert!(text.contains("\"body\":\"hi\""), "{text}");

    let parsed = round_trip(&envelope, b).expect("round trips");
    assert_eq!(parsed.payload_str(), Some(text));
}

#[test]
fn an_oversized_payload_is_refused_at_construction() {
    let (a, b) = (device(), device());
    let big = "x".repeat(MAX_PAYLOAD_LEN + 1);
    assert!(matches!(
        Envelope::outbound(spec("device.ping", a, b), Some(&big)),
        Err(EnvelopeError::PayloadTooLarge { .. })
    ));
}

#[test]
fn a_deeply_nested_payload_is_refused() {
    let (a, b) = (device(), device());

    // One level deeper than allowed, as *real* nesting. Building it by wrapping a string would
    // produce one JSON string with brackets inside it, which is one level deep — the check would
    // never fire and the test would pass for the wrong reason.
    let mut nested = serde_json::Value::Null;
    for _ in 0..=MAX_PAYLOAD_DEPTH {
        nested = serde_json::Value::Array(vec![nested]);
    }

    assert!(matches!(
        Envelope::outbound(spec("device.ping", a, b), Some(&nested)),
        Err(EnvelopeError::TooDeep { .. })
    ));

    // Exactly at the ceiling is accepted, so the limit is inclusive and not off by one.
    let mut allowed = serde_json::Value::Null;
    for _ in 0..MAX_PAYLOAD_DEPTH {
        allowed = serde_json::Value::Array(vec![allowed]);
    }
    assert!(Envelope::outbound(spec("device.ping", a, b), Some(&allowed)).is_ok());
}

#[test]
fn depth_counting_ignores_brackets_inside_strings() {
    // A payload whose *text* looks deeply nested but whose structure is flat. Counting bytes
    // without tracking strings would reject it.
    let (a, b) = (device(), device());
    let payload = json!({ "note": "{{{{[[[[ nested " });
    assert!(Envelope::outbound(spec("device.ping", a, b), Some(&payload)).is_ok());
}

#[test]
fn escaping_inside_strings_does_not_confuse_depth_counting() {
    let (a, b) = (device(), device());
    let payload = json!({ "quote": "he said \"{\" loudly" });
    assert!(Envelope::outbound(spec("device.ping", a, b), Some(&payload)).is_ok());
}
