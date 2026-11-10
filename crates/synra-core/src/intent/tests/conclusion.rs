use std::time::Duration;
use synra_protocol::error::ErrorCode;
use synra_protocol::ids::{DeviceId, IntentId};
use synra_protocol::SynraError;
use super::super::types::{Choice, IntentError, IntentState};
use super::{NOW, share, candidate, board, after_window};

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
