use std::sync::Arc;
use parking_lot::Mutex;
use super::super::{cancel, decide, dispatch};
use super::{invocation, item, local_device, set_that_accepts, set_that_accepts_without_a_place};

#[test]
fn cancelling_a_dispatched_intent_produces_a_withdrawal_for_the_far_side() {
    // ★ Cancelling here does not stop it there.
    //
    // A dispatched intent is running on another device, and that device hears about a change of mind only if it is
    // told. The first version of `cancel` was local-only: the other device finished work the user had withdrawn and
    // reported a result for it, which from this side looks like a cancellation that quietly did not take.
    //
    // ★ And the fact that it *was* dispatched lives in the state being replaced.
    //
    // Reading it after the move gives `Cancelled` and nothing else — no target, no request identifier — so the
    // cancellation is read first. That ordering is the whole of this test's reason for existing.
    let plugins = set_that_accepts_without_a_place("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
    let intent = routed["intent"].as_str().expect("an id").to_owned();
    let phone = "00000000-0000-4000-8000-0000000000ff";

    let _ = decide(&plugins, &board, local_device(), &intent, None, Some(phone), 2_000)
        .expect("dispatched");

    let change = cancel(&board, local_device(), &intent, "the user changed their mind")
        .expect("cancelled");
    let rendered = change.to_json();

    assert_eq!(rendered["state"], "cancelled", "{rendered}");
    assert_eq!(rendered["cancelledAt"], phone, "{rendered}");

    let outbound = change.outbound.as_ref().expect("a withdrawal to send");
    assert_eq!(outbound.to.to_string(), phone);
    assert_eq!(outbound.envelope.event.as_str(), "_synra.intent.cancel");
    let payload = synra_core::intent::remote::cancel_from(&outbound.envelope)
        .expect("a readable cancellation");
    assert_eq!(payload.reason, "the user changed their mind");
}

#[test]
fn a_withdrawal_from_another_device_stops_work_that_has_not_run_yet() {
    // The receiving half, in the case the design cares about: the work is **dispatching** and has not run, and the
    // sender says stop.
    //
    // The envelope names the request; `recall` finds the intent this device raised for that origin, and nothing else
    // may be touched — a lookup by anything else, such as the plugin it names, would let one device cancel another's
    // work.
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let request = synra_protocol::ids::RequestId::new();
    let asked = invocation(request);
    let phone = asked.from;

    // Raised the way `accept_remote` raises it — which is the state a device is in *between* receiving a request and
    // finishing it. Calling `accept_remote` here would run the action to completion, and a withdrawal that arrives
    // afterwards is a different case, covered below.
    let (id, _, created) = board.lock().raise(
        synra_core::intent::IntentSource::Direct {
            plugin_id: synra_protocol::ids::PluginId::try_from("@acme/opener".to_owned())
                .expect("a plugin id"),
            action: "open".to_owned(),
            params: serde_json::json!({ "url": "https://example.com" }),
            target: local_device(),
        },
        synra_core::intent::Choice::default(),
        Some(phone),
        Some(request),
        2_000,
    );
    assert!(created, "the request is new to this device");

    let withdrawal = synra_core::intent::remote::cancel(
        phone,
        local_device(),
        &synra_core::intent::remote::Cancel { reason: "the user changed their mind".to_owned() },
        request,
        synra_protocol::ids::TraceId::new(),
        3_000,
    )
    .expect("an envelope");

    let cancelled = synra_core::dispatch::orchestrate::accept_cancel(&board, &withdrawal)
        .expect("handled");

    assert_eq!(cancelled, Some(id), "it found the work that request raised");
    let state = board.lock().get(id).map(|intent| intent.state.kind().to_owned());
    assert_eq!(state.as_deref(), Some("cancelled"), "and stopped it");
}

#[test]
fn a_withdrawal_that_arrives_after_the_work_finished_does_not_undo_it() {
    // ★ The race, and the only honest answer to it.
    //
    // A cancellation can cross an `INTENT_RESULT` on the wire. When it does, the work has already happened — running a
    // plugin's action is not reversible by a later message — so the outcome stands. Quietly overwriting `succeeded`
    // with `cancelled` would erase the fact that the action ran, which is the one thing a user needs to know.
    let plugins = set_that_accepts("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let request = synra_protocol::ids::RequestId::new();
    let asked = invocation(request);
    let phone = asked.from;

    let _ = synra_core::dispatch::orchestrate::accept_remote(
        &plugins,
        &board,
        local_device(),
        &asked,
        2_000,
    )
    .expect("ran")
    .expect("an answer");

    let withdrawal = synra_core::intent::remote::cancel(
        phone,
        local_device(),
        &synra_core::intent::remote::Cancel { reason: "too late".to_owned() },
        request,
        synra_protocol::ids::TraceId::new(),
        3_000,
    )
    .expect("an envelope");

    let found = synra_core::dispatch::orchestrate::accept_cancel(&board, &withdrawal)
        .expect("handled")
        .expect("the work this request raised");

    let state = board.lock().get(found).map(|intent| intent.state.kind().to_owned());
    assert_eq!(state.as_deref(), Some("succeeded"), "the outcome stands: it ran");
}

#[test]
fn a_withdrawal_for_work_this_device_never_raised_is_not_an_error() {
    // The sender cannot know whether its invocation arrived, so it withdraws either way. Refusing would leave it
    // unable to clean up, and there is nothing here to stop.
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let withdrawal = synra_core::intent::remote::cancel(
        local_device(),
        "00000000-0000-4000-8000-0000000000ff".parse().expect("a device id"),
        &synra_core::intent::remote::Cancel { reason: "never mind".to_owned() },
        synra_protocol::ids::RequestId::new(),
        synra_protocol::ids::TraceId::new(),
        3_000,
    )
    .expect("an envelope");

    let nothing = synra_core::dispatch::orchestrate::accept_cancel(&board, &withdrawal)
        .expect("handled without complaint");

    assert!(nothing.is_none(), "there was nothing here to cancel");
}
