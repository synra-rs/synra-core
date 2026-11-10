use synra_protocol::ids::{DeviceId, RequestId};
use super::super::types::{Choice, IntentSource, IntentState};
use super::{NOW, plugin, share, board};

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
