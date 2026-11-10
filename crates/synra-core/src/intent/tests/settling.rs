use synra_protocol::ids::DeviceId;
use super::super::types::{Choice, IntentState};
use super::{NOW, share, candidate, board, after_window};

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
