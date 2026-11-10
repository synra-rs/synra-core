use crate::envelope::{Envelope, OutboundSpec};
use crate::event::EventName;
use crate::ids::{DeviceId, PluginId, TraceId};

mod classification;
mod coalescing;
mod patterns;

fn slug(text: &str) -> PluginId {
    PluginId::parse(&format!("@acme/{text}")).expect("valid plugin id")
}

fn envelope(event: &str, from: DeviceId, target: DeviceId) -> Envelope {
    Envelope::outbound(
        OutboundSpec {
            event: EventName::parse(event).expect("valid event"),
            target,
            from,
            trace_id: TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&()>,
    )
    .expect("builds")
}
