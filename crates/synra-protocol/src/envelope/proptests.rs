use proptest::prelude::*;
use serde_json::value::RawValue;

use crate::event::EventName;
use crate::ids::{DeviceId, TraceId};
use crate::limits::MAX_PAYLOAD_LEN;

use super::{Envelope, OutboundSpec};

fn arbitrary_event() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("device.ping"),
        Just("device.bye"),
        Just("_synra.device.changed"),
        Just("_plugin.@acme/chat.text"),
        Just("_plugin.@acme/chat.typing"),
    ]
}

proptest! {
    /// Anything that can be built can be written and read back unchanged. If this fails, two
    /// peers built from the same code disagree about a message.
    #[test]
    fn envelopes_round_trip(
        event in arbitrary_event(),
        payload in proptest::option::of("[a-z0-9 \"]{0,64}"),
    ) {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let spec = OutboundSpec {
            event: EventName::parse(event).expect("the generated names are valid"),
            target: b,
            from: a,
            trace_id: TraceId::new(),
            sent_at_ms: 1,
            ttl_ms: Some(5_000),
        };
        let envelope = Envelope::outbound(spec, payload.as_ref()).expect("builds");
        let text = serde_json::to_string(&envelope).expect("serialises");
        let parsed = Envelope::inbound(&RawValue::from_string(text).expect("valid"), b)
            .expect("round trips");
        prop_assert_eq!(parsed, envelope);
    }

    /// A payload that is too large is refused at construction rather than at the socket, so a
    /// caller learns about the mistake where it was made.
    #[test]
    fn oversized_payloads_are_refused(len in (MAX_PAYLOAD_LEN + 1)..(MAX_PAYLOAD_LEN + 512)) {
        let payload = "x".repeat(len);
        let spec = OutboundSpec {
            event: EventName::parse("device.ping").expect("valid"),
            target: DeviceId::new(),
            from: DeviceId::new(),
            trace_id: TraceId::new(),
            sent_at_ms: 1,
            ttl_ms: None,
        };
        let result = Envelope::outbound(spec, Some(&payload));
        // Checked without a pattern, because `prop_assert!` builds a message with `format!` and a
        // `{ .. }` pattern would be read as a format placeholder.
        prop_assert!(result.is_err(), "a payload of {} bytes should be refused", len);
        prop_assert!(result.unwrap_err().to_string().contains("exceeds the ceiling"));
    }
}
