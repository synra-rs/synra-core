use serde_json::value::RawValue;

use crate::event::EventName;
use crate::ids::{DeviceId, TraceId};

use super::{Envelope, EnvelopeError, OutboundSpec};

mod addressing;
mod payload;
mod wire;

fn device() -> DeviceId {
    DeviceId::new()
}

fn spec(event: &str, from: DeviceId, target: DeviceId) -> OutboundSpec {
    OutboundSpec {
        event: EventName::parse(event).expect("valid event"),
        target,
        from,
        trace_id: TraceId::new(),
        sent_at_ms: 1_000,
        ttl_ms: None,
    }
}

/// Serialises and re-parses, which is what every assertion about the wire actually tests.
fn round_trip(envelope: &Envelope, local: DeviceId) -> Result<Envelope, EnvelopeError> {
    let text = serde_json::to_string(envelope).expect("serialises");
    Envelope::inbound(&RawValue::from_string(text).expect("valid"), local)
}
