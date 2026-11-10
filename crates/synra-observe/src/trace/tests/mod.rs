use super::*;
use synra_protocol::TraceId;
use synra_protocol::envelope::Envelope;
use synra_protocol::event::EventName;
use synra_protocol::ids::DeviceId;

fn envelope_with_trace(trace_id: TraceId) -> Envelope {
    Envelope::outbound(
        synra_protocol::envelope::OutboundSpec {
            event: EventName::parse("device.ping").expect("valid"),
            target: DeviceId::new(),
            from: DeviceId::new(),
            trace_id,
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&()>,
    )
    .expect("builds")
}

mod context;
mod sampling;
mod ring;
