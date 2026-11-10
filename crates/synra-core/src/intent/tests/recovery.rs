use synra_protocol::ids::{DeviceId, IntentId, RequestId};
use super::super::types::{Choice, IntentState};
use super::{NOW, share, candidate, board};

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
