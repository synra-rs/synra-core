use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::ids::TraceId;

use super::super::wire::{Message, classify};
use super::{A, B, device, envelope_of};

#[test]
fn every_message_name_is_one_the_protocol_declares() {
    // ★ The names are the protocol's, and a transfer that used a name outside its set would be a message the far end
    // refuses as an unknown event.
    for message in [
        Message::Request,
        Message::Chunk,
        Message::Complete,
        Message::Abort,
        Message::Progress,
    ] {
        assert!(
            EventName::parse(message.name()).is_ok(),
            "{} is not a name this build accepts",
            message.name()
        );
        assert!(
            synra_protocol::event::DataPlaneEvent::from_str_opt(message.name()).is_some(),
            "{} is not a data-plane event",
            message.name()
        );
    }
}

#[test]
fn a_classified_message_is_recognised_and_a_stranger_is_not() {
    // ★ A link carries every kind of message, so a dispatcher that claimed an unrelated event would break whichever
    // feature owned it.
    assert_eq!(classify(&envelope_of(Message::Request)), Some(Message::Request));
    assert_eq!(classify(&envelope_of(Message::Progress)), Some(Message::Progress));

    let stranger = Envelope::outbound(
        OutboundSpec {
            event: EventName::parse("device.ping").expect("a name"),
            target: device(B),
            from: device(A),
            trace_id: TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&serde_json::Value>,
    )
    .expect("builds");
    assert_eq!(classify(&stranger), None, "an unrelated event was claimed");
}
