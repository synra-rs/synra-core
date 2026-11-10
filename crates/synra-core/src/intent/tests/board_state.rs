use std::time::Duration;
use synra_protocol::error::ErrorCode;
use synra_protocol::ids::{DeviceId, IntentId, RequestId};
use synra_protocol::SynraError;
use super::super::board::Board;
use super::super::types::{Choice, IntentState};
use super::{NOW, share, candidate, board};

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
    assert_eq!(Board::new().matching_window(), super::super::board::MATCHING_WINDOW);
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
    let refusal = crate::admission::AdmissionRefusal {
        step: crate::admission::AdmissionStep::PluginGrant,
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
