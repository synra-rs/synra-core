use synra_protocol::ids::{DeviceId, IntentId, RequestId};
use super::super::board::{Board, CandidateChoice};
use super::super::types::{Choice, IntentError, IntentState};
use super::{NOW, plugin, share, candidate, board, after_window};

#[test]
fn a_user_choice_that_was_never_offered_is_refused() {
    // ★ The choice arrives from an interface, so it is input. Acting on one that was never shown would run something
    // the user did not choose.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", None));
    let _ = board.settle(id, after_window());

    let refused = board.choose(id, &CandidateChoice::new(plugin("@acme/evil"), "exfiltrate"));
    assert!(
        matches!(refused, Err(IntentError::NotACandidate { .. })),
        "{refused:?}"
    );
    // And nothing moved.
    assert!(matches!(
        board.get(id).expect("on the board").state,
        IntentState::Choosing { .. }
    ));
}

#[test]
fn a_choice_with_a_target_goes_to_confirmation_and_without_one_stays_a_question() {
    let target = DeviceId::new();

    let mut with_target = board();
    let (id, ..) = with_target.raise(share(), Choice::AlwaysAsk, None, None, NOW);
    let _ = with_target.offer(id, candidate("@acme/browser", "open", Some(target)));
    let _ = with_target.settle(id, after_window());
    let chosen = with_target
        .choose(id, &CandidateChoice::new(plugin("@acme/browser"), "open"))
        .expect("a choice");
    assert!(matches!(chosen, IntentState::Confirming { .. }), "{chosen:?}");

    let mut without_target = board();
    let (id, ..) = without_target.raise(share(), Choice::AlwaysAsk, None, None, NOW);
    let _ = without_target.offer(id, candidate("@acme/browser", "open", None));
    let _ = without_target.settle(id, after_window());
    let chosen = without_target
        .choose(id, &CandidateChoice::new(plugin("@acme/browser"), "open"))
        .expect("a choice");
    // Still a question, because *where* is the part nobody has answered yet.
    assert!(matches!(chosen, IntentState::Choosing { .. }), "{chosen:?}");
}

#[test]
fn confirming_produces_a_dispatch_and_the_envelope_id_it_carries() {
    let mut board = board();
    let origin = DeviceId::new();
    let request = RequestId::new();
    let (id, ..) = board.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));
    let _ = board.settle(id, after_window());

    let (candidate, envelope) = board.confirm(id).expect("a dispatch");
    assert_eq!(candidate.planned.action, "open");
    // ★ The id the envelope carries is the one the request arrived with. Minting a fresh one here would make a resend
    // after a lost answer look like a *second* request to the receiving side's idempotency cache — which is the same
    // as running the user's action twice.
    assert_eq!(envelope, request);
    // And the dispatch is now running, which is why confirming again is refused rather than answered twice.
    match board.confirm(id) {
        Err(IntentError::WrongState { attempted, current }) => {
            assert_eq!(attempted, "confirm");
            assert_eq!(current, "dispatching");
        }
        other => panic!("a second confirm must be refused, got {other:?}"),
    }
}

#[test]
fn a_dispatch_is_found_by_the_request_and_the_device_it_went_to() {
    // ★ Both halves of the pair, because a reply carries both: the request it answers (`reply_to`) and the device that
    // answered. A lookup on either one alone would apply one device's outcome to another device's work.
    let mut board = board();
    let target = DeviceId::new();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(target)));
    let _ = board.settle(id, after_window());
    let (_, request) = board.confirm(id).expect("a dispatch");

    assert_eq!(board.dispatched_to(request, target), Some(id));
    assert_eq!(board.dispatched_to(request, DeviceId::new()), None, "another device is another dispatch");
    assert_eq!(board.dispatched_to(RequestId::new(), target), None, "another request is another dispatch");

    // Once it concludes it is no longer dispatched to anything, which is what stops a late duplicate from being applied.
    let _ = board.conclude(id, Ok(serde_json::json!("opened")), 1);
    assert_eq!(board.dispatched_to(request, target), None);
}

#[test]
fn confirming_something_that_is_not_waiting_is_refused_with_both_states_named() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);

    // Still matching: a dispatch now would be a dispatch of a candidate nobody offered.
    match board.confirm(id) {
        Err(IntentError::WrongState { attempted, current }) => {
            assert_eq!(attempted, "confirm");
            assert_eq!(current, "matching");
        }
        other => panic!("expected a wrong-state refusal, got {other:?}"),
    }
    assert!(matches!(board.confirm(IntentId::new()), Err(IntentError::Unknown { .. })));
}

/// An intent whose one candidate named no device, which is the state that had no way out.
fn waiting_for_a_place(mut board: Board) -> (Board, IntentId) {
    let (id, _, _) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/opener", "open", None));
    let _ = board.settle(id, after_window());
    (board, id)
}

#[test]
fn aiming_answers_the_question_a_targetless_candidate_asks() {
    // ★ The state that could not be advanced.
    //
    // A candidate that named no device settles into `Choosing` — which is the question "where should this run?" — and
    // nothing answered it: `choose` puts a targetless candidate straight back into `Choosing`, and `confirm` refuses
    // anything that is not `Confirming`. So an action could be proposed and never performed.
    let (mut board, id) = waiting_for_a_place(board());
    let place = DeviceId::new();

    let state = board.aim(id, place).expect("the question is answerable");

    assert_eq!(state.kind(), "confirming");
    // And it is now confirmable, which is what "the question was answered" means — a state name alone would pass for a
    // transition that led nowhere.
    let (confirmed, _) = board.confirm(id).expect("and the intent can move on");
    assert_eq!(confirmed.plugin_id, plugin("@acme/opener"));
}

#[test]
fn aiming_at_an_intent_that_did_not_ask_is_refused() {
    // ★ "Cannot answer a prompt that is not being asked" is the answer that helps; a silent no-op, or attaching a
    // device to an intent that already had one, would leave a caller believing it had decided something.
    let mut board = board();
    let (id, _, _) = board.raise(share(), Choice::Automatic, None, None, NOW);

    // Still matching: no question has been asked yet.
    assert!(board.aim(id, DeviceId::new()).is_err());
    // And an intent that was never raised is not one this board can answer about.
    assert!(board.aim(IntentId::new(), DeviceId::new()).is_err());
}

#[test]
fn aiming_is_refused_while_the_user_is_choosing_between_plugins() {
    // ★ The two questions share one state, so the method has to tell them apart by the candidate count.
    //
    // With two candidates the question is "which plugin", and attaching a device to one the user has not picked would
    // answer a question they were not asked — by silently choosing for them.
    let mut board = board();
    let (id, _, _) = board.raise(share(), Choice::AlwaysAsk, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/one", "open", None));
    let _ = board.offer(id, candidate("@acme/two", "open", None));
    let _ = board.settle(id, after_window());

    let refused = board.aim(id, DeviceId::new());

    assert!(refused.is_err(), "which plugin is still unanswered");
    // And the intent is untouched: a refusal that had already moved the state would be worse than one that had not.
    assert_eq!(board.get(id).map(|intent| intent.state.kind()), Some("choosing"));
}

#[test]
fn aiming_cannot_replace_a_device_the_plugin_already_chose() {
    // ★ The authority hole the candidate-count inference left open.
    //
    // A candidate that suggested a device is one whose plugin answered *where*; the intent reaches `Choosing` only because
    // the user's setting asked them to confirm **which** plugin. `aim` used to accept a device there regardless — so a
    // caller could attach its own, and a share the plugin meant for a phone would run on this laptop.
    let place = DeviceId::new();
    let mut board = board();
    let (id, _, _) = board.raise(share(), Choice::AlwaysAsk, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/opener", "open", Some(place)));
    let _ = board.settle(id, after_window());

    // The same device it already named: there is nothing to answer.
    assert!(board.aim(id, place).is_err(), "the question was already answered");
    // And a different one: the caller does not get to overrule the plugin.
    assert!(
        board.aim(id, DeviceId::new()).is_err(),
        "a caller may not replace the device the candidate suggested"
    );
    // The intent is untouched, so a refusal did not half-apply.
    assert_eq!(board.get(id).map(|intent| intent.state.kind()), Some("choosing"));
}

#[test]
fn aiming_still_works_when_the_plugin_named_nothing() {
    // The other side of the same rule, so the refusal above is not just "aim never works".
    let (mut board, id) = waiting_for_a_place(board());
    let place = DeviceId::new();

    assert!(board.aim(id, place).is_ok());
    assert_eq!(board.get(id).map(|intent| intent.state.kind()), Some("confirming"));
}
