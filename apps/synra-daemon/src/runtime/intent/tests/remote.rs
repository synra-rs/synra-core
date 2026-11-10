use std::sync::Arc;
use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;
use super::super::{decide, dispatch, handle_event, snapshot};
use super::{invocation, item, local_device, set_that_accepts, set_that_accepts_without_a_place};

#[test]
fn a_request_from_another_device_runs_here_and_answers_with_the_outcome() {
    // ★ The other three of the design's four pieces.
    //
    // Doc 07: "send the message, run the plugin locally on receipt, reply with the result, and be idempotent by
    // request identifier". Sending landed a round ago; this is the receiving end — and the assertion that matters is
    // that the action actually ran, because a handler that answered `ok` without running anything would look
    // identical from the sender's side.
    let plugins = set_that_accepts("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let request = synra_protocol::ids::RequestId::new();

    let answer = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &invocation(request), 2_000)
        .expect("handled")
        .expect("an answer to send");

    assert_eq!(answer.event.as_str(), "_synra.intent.result");
    assert_eq!(answer.target, local_device(), "it goes back to whoever asked");
    assert_eq!(answer.reply_to, Some(request), "and it says which request it answers");
    let payload = synra_core::intent::remote::result_from(&answer).expect("a readable result");
    assert!(payload.is_ok(), "{payload:?}");
    assert_eq!(
        payload.into_parts().1,
        serde_json::json!("opened"),
        "the plugin ran, and its answer came back"
    );
}

#[test]
fn the_same_request_twice_runs_once_and_answers_twice() {
    // ★ The fourth piece, and the one whose failure is worst.
    //
    // A sender whose answer was lost resends. If the resend ran the action again, a user's action would happen twice —
    // and the second time is invisible from the sender, which sees one success. The board's `raise` is where this is
    // prevented, before anything is created, so a handler with its own cache would be a second answer to "have I seen
    // this" and the two would disagree the first time one was cleared.
    let plugins = set_that_accepts("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let request = synra_protocol::ids::RequestId::new();

    let first = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &invocation(request), 2_000)
        .expect("handled")
        .expect("an answer");
    let second = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &invocation(request), 3_000)
        .expect("handled")
        .expect("an answer again");

    // ★ The structural fact first, because it is the one that says whether the resend was recognised at all.
    //
    // `len` and not `live`: the first copy **concluded**, so it is no longer live, and a count of live intents would be
    // zero whether the resend was recognised or not — the shape of assertion that passes for the wrong reason, which is
    // what the first version of this test wrote.
    assert_eq!(board.lock().len(), 1, "one request is one intent");

    // A duplicate returns the recorded outcome, including its original elapsed time.
    let first = synra_core::intent::remote::result_from(&first).expect("a result");
    let second = synra_core::intent::remote::result_from(&second).expect("a result");
    assert_eq!(first, second);
}

#[test]
fn an_invocation_this_build_cannot_read_is_refused_rather_than_guessed_at() {
    // A payload that will not parse must not become a default: the default would name a plugin nobody chose and run
    // an action nobody asked for.
    let plugins = set_that_accepts("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let mut empty = invocation(synra_protocol::ids::RequestId::new());
    empty.payload = None;

    let refused = synra_core::dispatch::orchestrate::accept_remote(&plugins, &board, local_device(), &empty, 2_000);

    assert!(refused.is_err(), "an unreadable invocation is not a request");
}

#[test]
fn a_share_aimed_at_another_device_produces_an_envelope_instead_of_a_refusal() {
    // ★ This used to refuse, and the refusal was honest while nothing could send.
    //
    // `INTENT_INVOKE` was in the catalogue, in the automatic-ack table and in `inbound`'s kernel-event list, with no
    // sender and no receiver anywhere in the repository. The board already had both halves of the idempotency the
    // design asks for — `confirm` reuses a request id rather than minting a new one, and `recall` looks an arriving
    // request up by its origin — so what was missing was exactly this: build the message and hand it to a host.
    //
    // The other direction matters just as much, and is what the second half asserts: a remote target must **not**
    // run the plugin here. Running it would be doing the user's action on the machine they shared *from* rather than
    // the one they chose, and from the outside that looks identical to success.
    let plugins = set_that_accepts_without_a_place("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
    let intent = routed["intent"].as_str().expect("an id").to_owned();
    let phone = "00000000-0000-4000-8000-0000000000ff";

    let decided = decide(
        &plugins,
        &board,
        local_device(),
        &intent,
        None,
        Some(phone),
        2_000,
    )
    .expect("dispatched rather than refused");
    let answer = decided.to_json();

    assert_eq!(answer["state"], "dispatching", "{answer}");
    assert_eq!(answer["dispatchedTo"], phone, "{answer}");
    // ★ Nothing ran, and nothing failed. `ok` is false because no outcome exists yet, and `dispatchedTo` beside it is
    // what stops that being read as a failure.
    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["result"], serde_json::Value::Null, "{answer}");
    assert_eq!(answer["error"], serde_json::Value::Null, "{answer}");

    // The envelope is for the device the user chose, carries the event the far side listens for, and carries the
    // plugin's own arguments — not the share.
    let outbound = decided.outbound.as_ref().expect("an envelope to send");
    assert_eq!(outbound.to.to_string(), phone);
    assert_eq!(outbound.envelope.event.as_str(), "_synra.intent.invoke");
    assert_eq!(outbound.request_id, decided.request_id, "the id a resend is recognised by");
    // ★ And the envelope says so too. It used to carry a freshly minted id while the board kept `confirm`'s, so the
    // reply came back addressed to a request nothing on this side was waiting for.
    assert_eq!(
        outbound.envelope.request_id, decided.request_id,
        "the envelope carries the request id the board records"
    );
    let payload = synra_core::intent::remote::invoke_from(&outbound.envelope)
        .expect("a readable invocation");
    assert_eq!(payload.action, "open");
    assert_eq!(payload.args, serde_json::json!({ "url": "https://example.com" }));

    // And the plugin did not run: its scripted backend would have answered "opened" had it been called.
    let snapshot = snapshot(&board, &intent).expect("a snapshot");
    assert_eq!(snapshot["state"], "dispatching", "and it stays in flight: {snapshot}");
}

#[test]
fn a_remote_answer_turns_the_dispatch_into_the_outcome_it_reports() {
    // ★ The half nobody had: the sender's intent stayed `dispatching` for ever, because nothing applied the reply. The
    // far side could have run the action and this side would still be showing it as in flight.
    let plugins = set_that_accepts_without_a_place("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
    let intent = routed["intent"].as_str().expect("an id").to_owned();
    let phone = "00000000-0000-4000-8000-0000000000ff";
    let target: DeviceId = phone.parse().expect("a device id");

    let decided = decide(&plugins, &board, local_device(), &intent, None, Some(phone), 2_000)
        .expect("dispatched rather than refused");
    assert_eq!(decided.to_json()["state"], "dispatching", "nothing has happened yet");
    let outbound = decided.outbound.expect("an envelope to send");
    let invoke = outbound.envelope;

    let mut reply = synra_core::intent::remote::result(
        target,
        invoke.from,
        &synra_core::intent::remote::InvokeResult::from_execution(Ok("opened".to_owned()), 2),
        invoke.trace_id,
        3_000,
    )
    .expect("a result");
    // ★ The reply names the request it answers. Without it there is nothing to correlate, and the outcome would belong
    // to no dispatch at all.
    reply.reply_to = Some(invoke.request_id);

    let applied = synra_core::dispatch::orchestrate::apply_result(&board, &reply)
        .expect("the answer applies");
    assert_eq!(applied.map(|id| id.to_string()).as_deref(), Some(intent.as_str()));

    let after = snapshot(&board, &intent).expect("a snapshot");
    assert_eq!(after["state"], "succeeded", "{after}");
    // And a second copy of the same answer finds nothing in flight: the state is already final.
    assert_eq!(
        synra_core::dispatch::orchestrate::apply_result(&board, &reply)
            .expect("a repeated answer is ignored"),
        None
    );
}

#[test]
fn a_late_answer_from_another_device_is_applied_by_the_listener_callback() {
    // ★ The path a result takes when the sender gave up waiting: the receiver dials back, and the origin's listener
    // hands the envelope to this function. The assertion is on the board, not on a return value — an outcome that is
    // accepted and dropped would leave the intent dispatching for ever, which is the state this path exists to end.
    let plugins = set_that_accepts_without_a_place("@acme/opener");
    let board = Arc::new(Mutex::new(synra_core::intent::Board::new()));
    let routed = dispatch(&plugins, &board, &item(), 1_000).expect("routed");
    let intent = routed["intent"].as_str().expect("an id").to_owned();
    let phone = "00000000-0000-4000-8000-0000000000ff";
    let target: DeviceId = phone.parse().expect("a device id");

    let decided = decide(&plugins, &board, local_device(), &intent, None, Some(phone), 2_000)
        .expect("dispatched rather than refused");
    let invoke = decided.outbound.expect("an envelope to send").envelope;
    let mut reply = synra_core::intent::remote::result(
        target,
        invoke.from,
        &synra_core::intent::remote::InvokeResult::from_execution(Ok("opened".to_owned()), 2),
        invoke.trace_id,
        3_000,
    )
    .expect("a result");
    reply.reply_to = Some(invoke.request_id);

    let handled = handle_event(&plugins, &board, local_device(), &reply, 3_500);
    assert!(
        matches!(handled, synra_core::listener::KernelEventOutcome::Handled),
        "{handled:?}"
    );
    assert_eq!(
        snapshot(&board, &intent).expect("a snapshot")["state"],
        "succeeded",
        "the late answer was not applied"
    );

    // ★ And a second copy of the same answer is still `Handled`: `apply_result` finds nothing in flight and ignores
    // it. Reporting that as a refusal would make a harmless duplicate look like a protocol error.
    let repeat = handle_event(&plugins, &board, local_device(), &reply, 3_600);
    assert!(matches!(repeat, synra_core::listener::KernelEventOutcome::Handled), "{repeat:?}");
}
