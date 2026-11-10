use synra_protocol::ids::IntentId;
use super::super::types::{Choice, IntentState};
use super::{NOW, share, candidate, board, after_window};

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
