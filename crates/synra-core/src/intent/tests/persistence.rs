use synra_protocol::error::ErrorCode;
use synra_protocol::ids::{DeviceId, RequestId};
use super::super::board::CandidateChoice;
use super::super::types::{Choice, Intent, IntentSource, IntentState};
use super::{NOW, plugin, share, candidate, board, after_window};

/// Serialises an intent and reads it back, which is what the store does with it.
///
/// # Why this is asserted as **equality** rather than field by field
///
/// Because the failure this guards against is a derive that silently omits something. A test that checked the fields it
/// thought of would pass while a field nobody thought of was dropped — and the loss would appear as an intent that had
/// forgotten which plugin was going to answer it, discovered by a user rather than here.
fn through_json(intent: &Intent) -> Intent {
    let text = serde_json::to_string(intent).expect("an intent serialises");
    serde_json::from_str(&text).expect("and reads back")
}

/// Every intent on the board survives the trip.
///
/// Walks the same sequence a real one does — raise, offer, settle, confirm, conclude — and checks the round trip at each
/// stop, so a state that loses something is named by the step it was reached at.
#[test]
fn an_intent_survives_the_round_trip_at_every_step_of_its_life() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    assert_eq!(through_json(board.get(id).expect("raised")), *board.get(id).expect("raised"), "as raised");

    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));
    assert_eq!(through_json(board.get(id).expect("offered")), *board.get(id).expect("offered"), "as matching");

    let _ = board.settle(id, after_window());
    assert_eq!(through_json(board.get(id).expect("settled")), *board.get(id).expect("settled"), "as settled");

    let _ = board.confirm(id);
    assert_eq!(through_json(board.get(id).expect("confirmed")), *board.get(id).expect("confirmed"), "as confirmed");

    let _ = board.conclude(id, Ok(serde_json::json!({"opened":true})), 42);
    assert_eq!(through_json(board.get(id).expect("concluded")), *board.get(id).expect("concluded"), "as succeeded");
}

#[test]
fn a_refusal_survives_with_the_step_that_refused_it() {
    // ★ The one nested type that is not in this module: `AdmissionRefusal` carries an `AdmissionStep`, and a refusal
    // restored without the step it happened at would tell a plugin that something was wrong and not what.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.refuse(id, crate::admission::AdmissionRefusal {
        step: crate::admission::AdmissionStep::PluginGrant,
        code: ErrorCode::CapabilityDenied,
        detail: "the plugin was not granted it".to_owned(),
    });

    let intent = board.get(id).expect("refused");
    let restored = through_json(intent);

    assert_eq!(restored, *intent);
    match &restored.state {
        IntentState::Refused { refusal } => {
            assert_eq!(refusal.step, crate::admission::AdmissionStep::PluginGrant);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_cancelled_intent_keeps_its_reason() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.cancel(id, "the user changed their mind");

    let restored = through_json(board.get(id).expect("cancelled"));

    match &restored.state {
        IntentState::Cancelled { reason } => assert_eq!(reason, "the user changed their mind"),
        other => panic!("expected a cancellation, got {other:?}"),
    }
}

#[test]
fn every_choice_and_every_source_survives() {
    // The two enums with the most variants, and the ones that decide who gets asked — a `Choice` restored as its default
    // would turn a user's "always ask me" into a plugin acting on its own.
    let sources = [
        share(),
        IntentSource::Clipboard { target: Some(DeviceId::new()) },
        IntentSource::PluginUi {
            plugin_id: plugin("@acme/notes"),
            action: "create".to_owned(),
            params: serde_json::json!({ "title": "x" }),
        },
        IntentSource::Direct {
            plugin_id: plugin("@acme/notes"),
            action: "create".to_owned(),
            params: serde_json::json!({ "title": "x" }),
            target: DeviceId::new(),
        },
    ];
    let choices = [Choice::Automatic, Choice::AlwaysAsk, Choice::AskWhenAmbiguous, Choice::Never];

    for source in sources {
        for choice in choices {
            let mut board = board();
            let (id, ..) = board.raise(source.clone(), choice, None, None, NOW);
            let intent = board.get(id).expect("raised");

            let restored = through_json(intent);

            assert_eq!(restored.source, source, "the source decides who is asked");
            assert_eq!(restored.choice, choice, "and the choice decides whether anyone is");
            assert_eq!(restored, *intent);
        }
    }
}

#[test]
fn an_intent_from_a_peer_survives_with_its_origin_and_request() {
    // ★ `origin` and `request_id` are the idempotency key: a peer whose answer was lost resends the request, and the board
    // recognises it by these two. An intent restored without them would be run a second time.
    let mut board = board();
    let origin = DeviceId::new();
    let request = RequestId::new();
    let (id, ..) = board.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW);

    let restored = through_json(board.get(id).expect("raised"));

    assert_eq!(restored.origin, Some(origin));
    assert_eq!(restored.request_id, Some(request));
}

#[test]
fn a_dispatch_survives_so_a_restart_does_not_send_it_twice() {
    // The far side's work is identified by the request id in the outbound envelope, and that id is minted once. Restoring
    // a dispatched intent without it would make the next restart send the same work under a new id — which the far side
    // would then run, because it is a different request.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));
    let _ = board.settle(id, after_window());
    let target = DeviceId::new();
    let _ = board.aim(id, target);
    let (_, sent) = board.confirm(id).expect("a dispatch");

    let intent = board.get(id).expect("dispatching");
    let restored = through_json(intent);

    assert_eq!(restored, *intent);
    match &restored.state {
        IntentState::Dispatching { request_id, .. } => {
            // ★ The assertion this test exists for. The target is deliberately not compared: the board records where the
            // **chosen candidate** said it would run, which is not necessarily the device `aim` was told about — the first
            // version of this test asserted they matched, and was wrong about the board rather than the other way round.
            assert_eq!(*request_id, sent, "the same request, not a new one");
        }
        other => panic!("expected a dispatch, got {other:?}"),
    }
}

#[test]
fn the_serialised_intent_carries_every_field_it_has() {
    // ★ Why the **key set** and not only a round trip.
    //
    // The equality assertions above catch a dropped field only when the fixture sets that field to something other than the
    // default. A `#[serde(skip)]` on an `Option` that happens to be `None` — `origin`, `request_id` — round-trips perfectly
    // and loses the field the moment it is not `None`. That was demonstrated: skipping `origin` failed exactly one of the
    // tests above, and the four that assert whole-value equality stayed green.
    //
    // The key set does not depend on any value, so a field cannot be dropped without this failing.
    let mut board = board();
    let (id, ..) = board.raise(
        share(),
        Choice::AlwaysAsk,
        Some(DeviceId::new()),
        Some(RequestId::new()),
        NOW,
    );
    let json: serde_json::Value =
        serde_json::to_value(board.get(id).expect("raised")).expect("an intent serialises");

    let keys: Vec<&str> = json
        .as_object()
        .expect("an intent is an object")
        .keys()
        .map(String::as_str)
        .collect();

    assert_eq!(
        keys,
        vec!["id", "trace", "source", "state", "choice", "created_at_ms", "request_id", "origin"],
        "every field, whether or not this fixture gave it a value"
    );
}

#[test]
fn the_states_that_carry_something_carry_all_of_it() {
    // The three states with more than one piece of data. A state that dropped `candidates` would round-trip as itself and
    // restore an intent that had forgotten every answer it had received — and a user would be asked to choose from nothing.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    // ★ No suggested target, because a candidate that names a device is confirmed rather than asked about — the board only
    // asks when it has to. The first version of this test offered a targeted candidate and then asserted a `Choosing`
    // state that the board had correctly skipped.
    let _ = board.offer(id, candidate("@acme/browser", "open", None));

    let matching: serde_json::Value = serde_json::to_value(&board.get(id).expect("matching").state).expect("json");
    let keys: Vec<&str> = matching["Matching"].as_object().expect("a variant object").keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["deadline_ms", "candidates"], "a deadline and what has answered so far");
    assert_eq!(
        matching["Matching"]["candidates"].as_array().expect("an array").len(),
        1,
        "and the answer that arrived is in it"
    );

    let _ = board.settle(id, after_window());
    let choosing: serde_json::Value = serde_json::to_value(&board.get(id).expect("choosing").state).expect("json");
    let keys: Vec<&str> = choosing["Choosing"].as_object().expect("a variant object").keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["candidates"], "the same answers, waiting for a person");

    let _ = board.choose(id, &CandidateChoice::new(plugin("@acme/browser"), "open")).expect("chosen");
    // ★ A chosen candidate is not yet a confirmation: the board still needs to be told *where* to run it, and it is
    // `aim` that supplies that. The first version of this test expected `Confirming` immediately after `choose` and was
    // wrong about the sequence — which is the point of driving the board the way a caller does.
    let target = DeviceId::new();
    let _ = board.aim(id, target).expect("aimed");
    let confirming: serde_json::Value = serde_json::to_value(&board.get(id).expect("confirming").state).expect("json");
    let keys: Vec<&str> = confirming["Confirming"].as_object().expect("a variant object").keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["candidate", "target"], "what is about to run, and where");
    assert_eq!(
        confirming["Confirming"]["target"].as_str().expect("a device id"),
        target.to_string(),
        "and the device the user chose"
    );
}
