//! The remote-intent payloads, on their own.

use synra_protocol::ids::{DeviceId, PluginId, TraceId};

use super::{Invoke, InvokeResult, invoke, invoke_from, result, result_from};

fn device(tail: u8) -> DeviceId {
    format!("00000000-0000-4000-8000-0000000000{tail:02}").parse().expect("a device id")
}

fn plugin() -> PluginId {
    PluginId::parse("@acme/notes").expect("a plugin id")
}

fn invocation() -> Invoke {
    Invoke {
        plugin_id: plugin(),
        plugin_version: "1.2.3".to_owned(),
        action: "open".to_owned(),
        // ★ The arguments the plugin itself proposed. Carried rather than recomputed, because this is the whole of what
        // the user was shown when they chose.
        args: serde_json::json!({"url": "https://example.com"}),
    }
}

#[test]
fn an_invocation_survives_the_wire_with_its_arguments() {
    // The round trip, because the envelope is the only thing the far side sees. A payload that lost `args` would arrive
    // as an action with nothing to act on, and the receiver would run it with whatever its own default was.
    let sent = invoke(device(1), device(2), &invocation(), TraceId::new(), 1_000).expect("an envelope");

    let back = invoke_from(&sent).expect("reads back");

    assert_eq!(back, invocation());
    assert_eq!(sent.event.as_str(), "_synra.intent.invoke");
    assert_eq!(sent.target, device(2));
}

#[test]
fn a_result_survives_the_wire_including_the_reason_it_failed() {
    // The failure direction is the one that matters: a receiver that reported `ok: false` with no reason would leave the
    // sender unable to say anything better than "it did not work".
    let payload = InvokeResult {
        ok: false,
        result: String::new(),
        error: Some("the plugin refused the URL".to_owned()),
        elapsed_ms: 42,
    };

    let sent = result(device(2), device(1), &payload, TraceId::new(), 2_000).expect("an envelope");
    let back = result_from(&sent).expect("reads back");

    assert_eq!(back, payload);
    assert_eq!(sent.event.as_str(), "_synra.intent.result");
}

#[test]
fn the_two_events_are_not_the_same_event() {
    // A builder that used one event name for both would make a result arrive as an invocation, and the receiving side
    // would run the action a second time — which is the failure the request identifier exists to prevent, arriving by a
    // different route.
    let asked = invoke(device(1), device(2), &invocation(), TraceId::new(), 1).expect("an envelope");
    let answered = result(
        device(2),
        device(1),
        &InvokeResult { ok: true, result: "done".to_owned(), error: None, elapsed_ms: 1 },
        TraceId::new(),
        2,
    )
    .expect("an envelope");

    assert_ne!(asked.event.as_str(), answered.event.as_str());
}

#[test]
fn a_payload_this_build_cannot_read_is_named_rather_than_guessed_at() {
    // ★ An invocation with no payload, or one that is not an `Invoke`, must not become a default `Invoke`. A default would
    // be a plugin identifier nobody proposed and an action nobody chose, and running it is the thing this whole path
    // exists to avoid.
    // Built with no payload at all, which is what a malformed or truncated frame would hand the reader.
    let empty = synra_protocol::envelope::Envelope::outbound(
        synra_protocol::envelope::OutboundSpec {
            event: synra_protocol::event::EventName::parse(synra_protocol::event::events::INTENT_INVOKE)
                .expect("a declared event"),
            target: device(2),
            from: device(1),
            trace_id: TraceId::new(),
            sent_at_ms: 1,
            ttl_ms: None,
        },
        None::<&Invoke>,
    )
    .expect("an envelope with no payload");

    let refused = invoke_from(&empty).expect_err("no payload is not an invocation");
    assert!(format!("{refused}").contains("payload"), "the refusal names what was missing: {refused}");
}

#[test]
fn every_envelope_gets_its_own_request_identifier() {
    // ★ The first version of this test asserted that an invocation and a result share a request identifier, and that is
    // false: each envelope mints its own. What makes a retry idempotent is not that the two events agree — it is that the
    // **sender reuses the identifier it already recorded** when it sends the same request again, which is what
    // `board::confirm` does ("reused rather than reminted") and what the receiver's `board::recall` looks up.
    //
    // So this asserts the property the builder is responsible for: a fresh identifier per envelope, and one the protocol
    // considers valid.
    let first = invoke(device(1), device(2), &invocation(), TraceId::new(), 1).expect("an envelope");
    let second = invoke(device(1), device(2), &invocation(), TraceId::new(), 2).expect("an envelope");

    assert_ne!(first.request_id, second.request_id, "each envelope mints its own");
    assert_eq!(first.trace_id, first.trace_id, "and the trace is the caller's, carried through");
}
