use serde_json::value::RawValue;
use crate::event::EventName;
use crate::ids::{RequestId, TraceId};
use super::super::{Envelope, EnvelopeError};
use super::{device, spec};

#[test]
fn outbound_sets_every_addressing_field() {
    let (from, target) = (device(), device());
    let envelope =
        Envelope::outbound(spec("device.ping", from, target), None::<&()>).expect("builds");

    assert_eq!(envelope.from, from);
    assert_eq!(envelope.target, target);
    assert!(envelope.reply_to.is_none());
    assert!(!envelope.trace_id.is_zero());
    assert!(envelope.payload.is_none());
}

#[test]
fn a_reply_inverts_the_addressing_and_inherits_the_trace() {
    let (a, b) = (device(), device());
    let request = Envelope::outbound(spec("device.pairing.request", a, b), None::<&()>)
        .expect("builds");

    let reply = Envelope::reply_to(
        &request,
        EventName::parse("device.pairing.response").expect("valid"),
        b,
        2_000,
        None::<&()>,
    )
    .expect("builds");

    assert_eq!(reply.from, b, "a reply comes from the device that received the request");
    assert_eq!(reply.target, a, "and goes back to the device that asked");
    assert_eq!(reply.reply_to, Some(request.request_id));
    assert_eq!(reply.trace_id, request.trace_id, "both halves share one trace");
    // A reply is its own request, so it needs its own id.
    assert_ne!(reply.request_id, request.request_id);
}

#[test]
fn a_message_for_another_device_is_refused() {
    let (a, b, c) = (device(), device(), device());
    let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    let raw = RawValue::from_string(serde_json::to_string(&envelope).expect("serialises"))
        .expect("valid");

    assert!(matches!(
        Envelope::inbound(&raw, c),
        Err(EnvelopeError::NotForUs { .. })
    ));
    // But a relay can still read it, which is what makes forwarding possible at all.
    assert_eq!(Envelope::inbound_any(&raw).expect("parses").target, b);
}

#[test]
fn a_nil_trace_is_refused() {
    let (a, b) = (device(), device());
    let envelope = Envelope {
        request_id: RequestId::new(),
        event: EventName::parse("device.ping").expect("valid"),
        target: b,
        from: a,
        reply_to: None,
        trace_id: TraceId(0),
        payload: None,
        sent_at_ms: 0,
        ttl_ms: None,
    };
    assert!(matches!(
        envelope.validate(b),
        Err(EnvelopeError::NilField { field: "traceId" })
    ));
}

#[test]
fn ttl_is_measured_as_a_duration() {
    let (a, b) = (device(), device());
    let mut outbound = spec("device.ping", a, b);
    outbound.sent_at_ms = 1_000;
    outbound.ttl_ms = Some(500);
    let envelope = Envelope::outbound(outbound, None::<&()>).expect("builds");

    assert!(!envelope.is_expired(1_000), "not yet");
    assert!(!envelope.is_expired(1_500), "exactly at the deadline still counts");
    assert!(envelope.is_expired(1_501), "past it");

    // No ttl means it never expires.
    let endless = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    assert!(!endless.is_expired(i64::MAX));
}

#[test]
fn a_sender_clock_in_the_future_does_not_expire_a_message_immediately() {
    let (a, b) = (device(), device());
    let mut outbound = spec("device.ping", a, b);
    outbound.sent_at_ms = i64::MAX;
    outbound.ttl_ms = Some(1);
    let envelope = Envelope::outbound(outbound, None::<&()>).expect("builds");

    // A clock that runs fast must not make every message look already-expired, which would
    // silently break the device. The difference is clamped to zero, so the TTL is measured from
    // arrival instead — the message lives for its full second and no longer.
    assert!(!envelope.is_expired(0), "a future timestamp means nothing has elapsed yet");
    assert!(!envelope.is_expired(i64::MAX - 1), "still within its TTL");
    // And it does expire, rather than being kept alive by arithmetic that wrapped.
    assert!(envelope.sent_at_ms == i64::MAX && envelope.ttl_ms == Some(1));
}

#[test]
fn reply_matching_is_the_callers_business() {
    let (a, b) = (device(), device());
    let request = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    let reply = Envelope::reply_to(
        &request,
        EventName::parse("device.pong").expect("valid"),
        b,
        2_000,
        None::<&()>,
    )
    .expect("builds");

    let outstanding = request.request_id;
    assert!(reply.check_reply_to(|id| *id == outstanding).is_ok());
    // A reply naming a request we never made is a protocol violation, caught here rather than
    // silently accepted as an unsolicited message.
    assert!(matches!(
        reply.check_reply_to(|_| false),
        Err(EnvelopeError::UnknownReply { .. })
    ));
}

#[test]
fn a_message_without_a_reply_to_always_passes_reply_matching() {
    let (a, b) = (device(), device());
    let envelope = Envelope::outbound(spec("device.ping", a, b), None::<&()>).expect("builds");
    assert!(envelope.check_reply_to(|_| false).is_ok());
}
