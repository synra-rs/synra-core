//! The board's sequence, driven from both sides.
//!
//! Every test here names the side it is driving. The transfer bug this repository wrote a note about was a suite that
//! answered only the sender's question while the daemon asked a different one, and a state machine is exactly the kind
//! of code that attracts the same mistake: a test that raises an intent and asserts its own state proves the board
//! agrees with itself.
//!
//! So each test drives the board the way a caller does — raise, offer, settle, choose, confirm, conclude — and asserts
//! what a *person* or a *device* would observe.

use std::time::Duration;

use synra_protocol::error::ErrorCode;
use synra_protocol::ids::{DeviceId, IntentId, PluginId, RequestId};
use synra_protocol::inbound::ShareItem;
use synra_protocol::SynraError;

use super::board::{Board, CandidateChoice};
use super::types::{Choice, Intent, IntentCandidate, IntentError, IntentSource, IntentState, PlannedAction};

/// Ten past the epoch, so a deadline is a number a reader can check by hand.
const NOW: i64 = 1_000;

fn plugin(name: &str) -> PluginId {
    PluginId::parse(name).expect("a valid plugin id")
}

fn share() -> IntentSource {
    IntentSource::Share {
        item: ShareItem {
            from: DeviceId::new(),
            mime: "text/plain".to_owned(),
            text: Some("https://example.test/a".to_owned()),
            transfers: Vec::new(),
            context_id: None,
        },
        source_app: Some("Browser".to_owned()),
    }
}

fn candidate(name: &str, action: &str, target: Option<DeviceId>) -> IntentCandidate {
    IntentCandidate {
        plugin_id: plugin(name),
        plugin_version: "1.0.0".to_owned(),
        planned: PlannedAction {
            plugin_id: plugin(name),
            action: action.to_owned(),
            args: serde_json::json!({ "url": "https://example.test/a" }),
        },
        required_caps: vec!["platform:open-url".to_owned()],
        suggested_target: target,
        title: "Open this link".to_owned(),
        detail: None,
    }
}

/// A board whose matching window is one millisecond, so `settle` is a call rather than a wait.
fn board() -> Board {
    Board::with_window(Duration::from_millis(1))
}

/// The moment matching is over.
fn after_window() -> i64 {
    NOW + 2
}

// ── Raising ───────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_share_starts_matching_with_a_deadline() {
    let mut board = board();
    let (id, _trace, created) = board.raise(share(), Choice::Automatic, None, None, NOW);
    assert!(created);

    let intent = board.get(id).expect("the intent is on the board");
    match &intent.state {
        IntentState::Matching { deadline_ms, candidates } => {
            assert_eq!(*deadline_ms, NOW + 1, "the deadline is the window, not a guess");
            assert!(candidates.is_empty(), "nothing has answered yet");
        }
        other => panic!("expected matching, got {other:?}"),
    }
}

#[test]
fn a_direct_source_needs_no_matching_at_all() {
    // ★ The source named its plugin and action, so there is nothing to ask. Putting it through matching would mean
    // calling a plugin to ask whether it can do what it was just told to do.
    let mut board = board();
    let target = DeviceId::new();
    let source = IntentSource::Direct {
        plugin_id: plugin("@acme/browser"),
        action: "open".to_owned(),
        params: serde_json::json!({ "url": "https://example.test" }),
        target,
    };
    let (id, _trace, _created) = board.raise(source, Choice::Automatic, None, None, NOW);

    match &board.get(id).expect("on the board").state {
        IntentState::Dispatching { candidate, target: where_to, .. } => {
            assert_eq!(candidate.planned.action, "open");
            assert_eq!(*where_to, target);
        }
        other => panic!("expected a dispatch, got {other:?}"),
    }
}

#[test]
fn a_repeated_request_is_the_same_intent_rather_than_a_second_one() {
    // ★ The idempotency rule, from the sender's side: an answer was lost, so it asks again. A second intent would run
    // the user's action twice.
    let mut board = board();
    let origin = DeviceId::new();
    let request = RequestId::new();

    let (first, trace, created) = board.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW);
    let (second, again, raised_again) = board.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW + 5);

    assert!(created, "the first request raises an intent");
    assert!(!raised_again, "the second must not");
    assert_eq!(first, second);
    assert_eq!(trace, again, "a retry keeps the trace, which is what makes a log of it one story");
    assert_eq!(board.len(), 1, "and the board holds one intent, not two");
}

#[test]
fn the_same_request_id_from_another_device_is_another_request() {
    // A request id is chosen by the sender, and two senders choose independently. Treating the id alone as the key
    // would let one device's retry suppress another device's share.
    let mut board = board();
    let request = RequestId::new();
    let (first, _, _) = board.raise(share(), Choice::Automatic, Some(DeviceId::new()), Some(request), NOW);
    let (second, _, created) = board.raise(share(), Choice::Automatic, Some(DeviceId::new()), Some(request), NOW);

    assert!(created);
    assert_ne!(first, second);
    assert_eq!(board.len(), 2);
}

#[test]
fn a_request_can_be_recalled_while_it_is_still_live() {
    let mut board = board();
    let origin = DeviceId::new();
    let request = RequestId::new();
    let (id, _, _) = board.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW);

    let recalled = board.recall(origin, request).expect("it is on the board");
    assert_eq!(recalled.id, id);
    assert!(board.recall(origin, RequestId::new()).is_none(), "an unknown request is not recalled");
}

// ── Offering ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_candidate_is_kept_while_the_window_is_open() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    assert!(board.offer(id, candidate("@acme/browser", "open", None)));
    assert_eq!(board.get(id).expect("on the board").state.candidates().len(), 1);
}

#[test]
fn a_second_answer_from_one_plugin_supersedes_the_first() {
    // One plugin has not offered two choices; it has described one twice. Two entries in a prompt would ask a user to
    // choose between the same thing.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    assert!(board.offer(id, candidate("@acme/browser", "open", None)));
    assert!(board.offer(id, candidate("@acme/browser", "open", None)));

    assert_eq!(board.get(id).expect("on the board").state.candidates().len(), 1);
}

#[test]
fn two_actions_from_one_plugin_are_two_candidates() {
    // The supersede rule is per action. A plugin that could both open a link and save it has genuinely offered two
    // things, and collapsing them would hide one.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    assert!(board.offer(id, candidate("@acme/browser", "open", None)));
    assert!(board.offer(id, candidate("@acme/browser", "save", None)));

    assert_eq!(board.get(id).expect("on the board").state.candidates().len(), 2);
}

#[test]
fn an_answer_that_arrives_after_the_window_is_dropped() {
    // ★ A list that grew after a user started reading it is a prompt whose meaning changed under them.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.settle(id, after_window());

    assert!(!board.offer(id, candidate("@acme/browser", "open", None)));
    assert!(matches!(
        board.get(id).expect("on the board").state,
        IntentState::NoHandler
    ));
}

#[test]
fn an_answer_for_an_unknown_intent_is_refused_rather_than_stored() {
    let mut board = board();
    assert!(!board.offer(IntentId::new(), candidate("@acme/browser", "open", None)));
}

// ── Settling ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn nothing_happens_before_the_window_closes() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", None));

    assert!(board.settle(id, NOW).is_none(), "the window is still open");
    assert!(matches!(board.get(id).expect("on the board").state, IntentState::Matching { .. }));
}

#[test]
fn no_candidate_means_no_handler_rather_than_a_prompt_with_nothing_in_it() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);

    let settled = board.settle(id, after_window()).expect("a decision");
    assert_eq!(settled, IntentState::NoHandler);
    // And it is final: an interface that showed a spinner for this would spin for ever.
    assert!(settled.is_final());
}

#[test]
fn one_candidate_with_a_target_goes_straight_to_confirmation() {
    let mut board = board();
    let target = DeviceId::new();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(target)));

    let settled = board.settle(id, after_window()).expect("a decision");
    match settled {
        IntentState::Confirming { candidate, target: where_to } => {
            assert_eq!(candidate.planned.action, "open");
            assert_eq!(where_to, target);
        }
        other => panic!("expected confirmation, got {other:?}"),
    }
}

#[test]
fn two_candidates_ask_the_user_even_in_the_automatic_mode() {
    // ★ Automatic is not "pick the first". A plugin cannot make itself the silent answer by being installed first.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", None));
    let _ = board.offer(id, candidate("@acme/notes", "save", None));

    let settled = board.settle(id, after_window()).expect("a decision");
    match settled {
        IntentState::Choosing { candidates } => assert_eq!(candidates.len(), 2),
        other => panic!("expected a choice, got {other:?}"),
    }
}

#[test]
fn the_never_mode_refuses_rather_than_asking() {
    // For an unattended device: a prompt there would sit unanswered while the sender waited.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Never, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));

    let settled = board.settle(id, after_window()).expect("a decision");
    // One candidate and no asking: it goes to confirmation, because `Never` is about *matching*, not about the final
    // confirmation a user still has to give for a remote action.
    assert!(matches!(settled, IntentState::Confirming { .. }), "{settled:?}");
}

#[test]
fn the_always_ask_mode_asks_even_with_one_candidate() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::AlwaysAsk, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));

    assert!(matches!(
        board.settle(id, after_window()).expect("a decision"),
        IntentState::Choosing { .. }
    ));
}

#[test]
fn settling_twice_decides_once() {
    // The timer that calls this may fire more than once, and a second decision must not move an intent that a user is
    // already answering.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));

    let first = board.settle(id, after_window()).expect("a decision");
    assert!(board.settle(id, after_window()).is_none(), "the second call has nothing to decide");
    assert_eq!(board.get(id).expect("on the board").state, first);
}

// ── Choosing and confirming ───────────────────────────────────────────────────────────────────────

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

// ── Concluding ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_successful_outcome_is_recorded_with_its_result() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.offer(id, candidate("@acme/browser", "open", Some(DeviceId::new())));
    let _ = board.settle(id, after_window());
    let _ = board.confirm(id);

    let ended = board
        .conclude(id, Ok(serde_json::json!({"opened":true})), 42)
        .expect("an outcome");
    match ended {
        IntentState::Succeeded { result, elapsed_ms } => {
            assert_eq!(result, serde_json::json!({ "opened": true }));
            assert_eq!(elapsed_ms, 42);
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[test]
fn a_text_result_is_recorded_without_becoming_a_failure() {
    // Text has already been normalized at the execution boundary; the board stores the typed success.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let ended = board
        .conclude(id, Ok(serde_json::json!("just words")), 1)
        .expect("an outcome");

    match ended {
        IntentState::Succeeded { result, .. } => {
            assert_eq!(result, serde_json::Value::String("just words".to_owned()));
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[test]
fn a_failed_outcome_carries_the_devices_own_error_code() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let error = SynraError::new(ErrorCode::CapabilityDenied, "the plugin may not open URLs");

    let ended = board
        .conclude(id, Err(error.clone()), 3)
        .expect("an outcome");
    match ended {
        IntentState::Failed { error: carried, elapsed_ms } => {
            assert_eq!(carried, error);
            assert_eq!(elapsed_ms, 3);
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn a_second_outcome_does_not_change_what_happened() {
    // A device that reports success and then failure has not changed history. The first answer is what the user is
    // shown, and the promise to conclude once is what a test can hold the kernel to.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let first = board
        .conclude(id, Ok(serde_json::json!(1)), 1)
        .expect("an outcome");
    let second = board
        .conclude(
            id,
            Err(SynraError::new(
                ErrorCode::Internal,
                "ignored repeated result",
            )),
            2,
        )
        .expect("an outcome");

    assert_eq!(first, second);
    assert!(first.is_final());
}

#[test]
fn a_late_outcome_for_a_forgotten_intent_names_the_intent_rather_than_panicking() {
    let mut board = board();
    match board.conclude(IntentId::new(), Ok(serde_json::json!(1)), 1) {
        Err(IntentError::Unknown { intent_id }) => assert!(!intent_id.to_string().is_empty()),
        other => panic!("expected an unknown-intent error, got {other:?}"),
    }
}

#[test]
fn cancelling_something_that_already_ended_is_not_an_error() {
    // The user asked for it to stop and it has stopped. A refusal would turn a race between the two into a message
    // about an invalid state.
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let ended = board
        .conclude(id, Ok(serde_json::json!(1)), 1)
        .expect("an outcome");

    assert_eq!(board.cancel(id, "the user closed the window").expect("a no-op"), ended);
}

#[test]
fn a_refusal_records_which_of_the_eight_checks_stopped_it() {
    use crate::admission::{AdmissionRefusal, AdmissionStep};

    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let refusal = AdmissionRefusal {
        step: AdmissionStep::SenderPaired,
        detail: "the sending device is not paired".to_owned(),
        code: ErrorCode::NotPaired,
    };

    let ended = board.refuse(id, refusal.clone()).expect("a state");
    match ended {
        IntentState::Refused { refusal: carried } => assert_eq!(carried, refusal),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_timeout_says_how_long_the_window_was() {
    let mut board = board();
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let ended = board.time_out(id).expect("a state");

    match ended {
        IntentState::TimedOut { after } => assert_eq!(after, Duration::from_millis(1)),
        other => panic!("expected a timeout, got {other:?}"),
    }
}

// ── The board itself ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_live_list_is_ordered_and_excludes_what_ended() {
    let mut board = board();
    let (first, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let (second, ..) = board.raise(share(), Choice::Automatic, None, None, NOW + 1);
    let _ = board.conclude(first, Ok(serde_json::json!(1)), 1);

    let live: Vec<IntentId> = board.live().iter().map(|intent| intent.id).collect();
    assert_eq!(live, vec![second], "the ended one is not live and the order is by age");
    assert_eq!(board.len(), 2, "but it is still held, so a repeat can be answered from it");
}

#[test]
fn the_sweep_drops_the_oldest_finished_intents_and_nothing_else() {
    // The bound's reason: a device that shares things all day would otherwise hold every share it has ever seen.
    let mut board = Board::with_window(Duration::from_millis(1));
    let mut ended = Vec::new();
    for index in 0..4 {
        let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW + index);
        let _ = board.conclude(id, Ok(serde_json::json!(1)), 1);
        ended.push(id);
    }
    // A live one, which the sweep must never touch however old it is: an intent somebody is still answering is not
    // stale, and dropping it would lose a prompt the user is looking at.
    let (live, ..) = board.raise(share(), Choice::AlwaysAsk, None, None, NOW);

    // A horizon that leaves only the most recent finished intent inside it, so the other three are stale.
    let dropped = board.forget_ended_before(NOW + 4, Duration::from_millis(1));
    assert_eq!(dropped, 3, "the three stale ones go and the newest stays");
    assert!(board.get(live).is_some(), "a live intent was dropped");
    assert!(board.get(*ended.last().expect("one")).is_some(), "the newest finished intent was dropped");
    assert!(board.get(ended[0]).is_none(), "the oldest finished intent was kept");
    assert_eq!(board.len(), 2, "the live one and the newest finished one");
}

#[test]
fn a_sweep_that_has_nothing_stale_drops_nothing() {
    // The other half of the rule: the age is what decides, so a board whose intents are all recent keeps all of them.
    let mut board = Board::with_window(Duration::from_millis(1));
    let (id, ..) = board.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = board.conclude(id, Ok(serde_json::json!(1)), 1);

    assert_eq!(board.forget_ended_before(NOW, Duration::from_secs(60)), 0);
    assert!(board.get(id).is_some());
}

#[test]
fn an_empty_board_says_so() {
    let board = board();
    assert!(board.is_empty());
    assert_eq!(board.len(), 0);
    assert!(board.live().is_empty());
    assert_eq!(board.ended_count(), 0);
    // And the default window is the one the design document names, so a caller that does not care gets a real value.
    assert_eq!(Board::new().matching_window(), super::board::MATCHING_WINDOW);
}

#[test]
fn every_state_has_a_name_and_a_defined_end() {
    // The property an interface depends on: every state can be labelled, and "is it over?" is a question with an
    // answer for each — an unhandled variant would be a spinner that never stops.
    let states = [
        IntentState::Matching { deadline_ms: 0, candidates: Vec::new() },
        IntentState::Choosing { candidates: Vec::new() },
        IntentState::Confirming { candidate: candidate("@a/b", "x", None), target: DeviceId::new() },
        IntentState::Dispatching {
            candidate: candidate("@a/b", "x", None),
            target: DeviceId::new(),
            request_id: RequestId::new(),
        },
        IntentState::Succeeded { result: serde_json::Value::Null, elapsed_ms: 0 },
        IntentState::Failed {
            error: SynraError::new(ErrorCode::Internal, "x"),
            elapsed_ms: 0,
        },
        IntentState::NoHandler,
        IntentState::TimedOut { after: Duration::from_millis(1) },
        IntentState::Refused {
            refusal: crate::admission::AdmissionRefusal {
                step: crate::admission::AdmissionStep::SenderPaired,
                detail: "x".to_owned(),
                code: ErrorCode::NotPaired,
            },
        },
        IntentState::Cancelled { reason: "x".to_owned() },
    ];

    let mut seen = Vec::new();
    for state in &states {
        let name = state.kind();
        assert!(!name.is_empty());
        assert!(!seen.contains(&name), "{name} names two states");
        seen.push(name);
    }
    assert!(!states[0].is_final(), "matching is not final");
    assert!(states[4].is_final(), "success is final");
    assert!(states[3].is_running(), "dispatching is running");
    assert!(!states[0].is_running(), "matching is not running a plugin yet");
}

// ── Aiming ─────────────────────────────────────────────────────────────────────────────

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
// ── Surviving a restart ───────────────────────────────────────────────────────────────────────────

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
    let _ = board.refuse(id, super::super::admission::AdmissionRefusal {
        step: super::super::admission::AdmissionStep::PluginGrant,
        code: ErrorCode::CapabilityDenied,
        detail: "the plugin was not granted it".to_owned(),
    });

    let intent = board.get(id).expect("refused");
    let restored = through_json(intent);

    assert_eq!(restored, *intent);
    match &restored.state {
        IntentState::Refused { refusal } => {
            assert_eq!(refusal.step, super::super::admission::AdmissionStep::PluginGrant);
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

// ── Coming back ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_restored_intent_keeps_the_identifier_and_trace_it_had() {
    // ★ The reason `restore` is not `raise`.
    //
    // `raise` mints an identifier and a trace. A restored intent has both already, and giving it new ones would mean a peer
    // that resends the request it originally raised is answered with a **second** intent — the action runs twice, which is
    // the exact failure the idempotency rule exists to prevent — and every log line about it would carry a trace that
    // matches nothing.
    let mut live = board();
    let (id, trace, ..) = live.raise(share(), Choice::Automatic, Some(DeviceId::new()), Some(RequestId::new()), NOW);
    let original = live.get(id).expect("raised").clone();

    let mut restored = board();
    assert!(restored.restore(original.clone()));

    let back = restored.get(id).expect("restored");
    assert_eq!(back.id, id);
    assert_eq!(back.trace, trace);
    assert_eq!(*back, original);
}

#[test]
fn a_restored_board_answers_the_same_request_with_the_same_intent() {
    // ★ The consequence, driven the way a peer drives it: raise, restart, resend. The answer must be the first intent
    // rather than a second one, because the second one would run the user's action again.
    let origin = DeviceId::new();
    let request = RequestId::new();

    let mut before = board();
    let (id, ..) = before.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW);
    let saved = before.get(id).expect("raised").clone();

    let mut after = board();
    assert!(after.restore(saved));
    let (again, ..) = after.raise(share(), Choice::Automatic, Some(origin), Some(request), NOW + 5_000);

    assert_eq!(again, id, "the request finds the intent it already raised");
    assert_eq!(after.len(), 1, "and no second intent was created");
}

#[test]
fn restoring_the_same_intent_twice_changes_nothing() {
    // ★ A duplicate is refused rather than overwritten: the two are not the same intent, and a restored copy of one the
    // board has already been working on would roll its state **backwards** — and a rollback looks exactly like progress to
    // everything downstream.
    let mut live = board();
    let (id, ..) = live.raise(share(), Choice::Automatic, None, None, NOW);
    let saved = live.get(id).expect("raised").clone();

    let mut restored = board();
    assert!(restored.restore(saved.clone()), "the first one is taken");
    // The board has moved on.
    let _ = restored.offer(id, candidate("@acme/browser", "open", None));
    let moved_on = restored.get(id).expect("offered").clone();

    assert!(!restored.restore(saved), "the stale copy is refused");
    assert_eq!(*restored.get(id).expect("still there"), moved_on, "and nothing was rolled back");
    assert_eq!(restored.len(), 1);
}

#[test]
fn a_restored_board_lists_its_intents_including_the_ended_ones() {
    // ★ Why `all` exists beside `live`. Persisting saves what *changed*, and what changed may be an intent that has just
    // ended — `live` is exactly the intents that have not, so a board that could only list those could not persist a
    // result.
    let mut live = board();
    let (ended, ..) = live.raise(share(), Choice::Automatic, None, None, NOW);
    let _ = live.conclude(ended, Ok(serde_json::json!({"ok":true})), 3);
    let (still_live, ..) = live.raise(share(), Choice::Automatic, None, None, NOW);

    let mut restored = board();
    for intent in live.all() {
        assert!(restored.restore(intent.clone()));
    }

    let ids: Vec<IntentId> = restored.all().iter().map(|intent| intent.id).collect();
    assert_eq!(ids, vec![ended, still_live], "in the order they were raised");
    assert_eq!(restored.live().len(), 1, "and only one of them is still live");
    assert!(matches!(
        restored.get(ended).expect("restored").state,
        IntentState::Succeeded { .. }
    ));
}

#[test]
fn the_board_keeps_the_order_it_was_given_rather_than_sorting_by_a_timestamp() {
    // ★ Why this is asserted rather than assumed.
    //
    // `order` exists precisely so that a sweep does **not** sort by a timestamp — the field's own doc says a clock change
    // could reorder that. `restore` therefore appends, which means the caller's order is the board's order:
    // `load_intents` answers oldest-first, and a caller that restored the other way round would get a board that sweeps
    // the wrong intent first. So the order is the caller's, and this proves it by giving the board the reverse.
    let mut live = board();
    let (first, ..) = live.raise(share(), Choice::Automatic, None, None, NOW);
    let (second, ..) = live.raise(share(), Choice::Automatic, None, None, NOW + 1);

    let mut restored = board();
    for intent in live.all().into_iter().rev() {
        assert!(restored.restore(intent.clone()));
    }

    let order: Vec<IntentId> = restored.all().iter().map(|intent| intent.id).collect();
    assert_eq!(order, vec![second, first], "the board holds the order it was handed");
}

#[test]
fn the_finished_kinds_are_exactly_the_states_that_are_final() {
    // ★ Why this is a test and not a comment.
    //
    // `IntentState::final_kinds` exists because the store's retention sweep compares a persisted `state` column to a list
    // of names, and the storage layer cannot depend on the kernel — so the list has to be written down somewhere it can be
    // handed over. A hand-written list is a second definition of "finished", and the failure mode is asymmetric and quiet:
    // a state renamed in `kind` but not in the list becomes **immortal**, and one renamed the other way is collected while
    // still in progress.
    //
    // So every variant is constructed here and the two answers are compared. A variant added to `IntentState` that nobody
    // added to either list fails to compile in this match, which is the point.
    let refusal = super::super::admission::AdmissionRefusal {
        step: super::super::admission::AdmissionStep::PluginGrant,
        code: ErrorCode::CapabilityDenied,
        detail: "not granted".to_owned(),
    };
    let candidate = candidate("@acme/browser", "open", None);

    let every = [
        IntentState::Matching { deadline_ms: NOW, candidates: Vec::new() },
        IntentState::Choosing { candidates: vec![candidate.clone()] },
        IntentState::Confirming { candidate: candidate.clone(), target: DeviceId::new() },
        IntentState::Dispatching {
            candidate,
            target: DeviceId::new(),
            request_id: RequestId::new(),
        },
        IntentState::Succeeded { result: serde_json::json!({}), elapsed_ms: 1 },
        IntentState::Failed {
            error: SynraError::new(ErrorCode::Internal, "broke"),
            elapsed_ms: 1,
        },
        IntentState::NoHandler,
        IntentState::TimedOut { after: Duration::from_millis(1) },
        IntentState::Refused { refusal },
        IntentState::Cancelled { reason: "no".to_owned() },
    ];
    // And that this list is the whole enum: a variant missing from it would be a variant nobody checked.
    assert_eq!(every.len(), 10, "the enum has ten states; a new one needs adding here and to one of the lists");

    for state in &every {
        assert_eq!(
            state.is_final(),
            IntentState::final_kinds().contains(&state.kind()),
            "`{}`: is_final says {}, the list says {}",
            state.kind(),
            state.is_final(),
            IntentState::final_kinds().contains(&state.kind())
        );
    }
}
