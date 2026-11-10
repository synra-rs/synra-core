use super::*;

#[test]
fn a_stateful_instance_is_bound_to_its_first_conversation() {
    // Handing a call to a different instance than the previous one is handing it to a plugin that has forgotten
    // what it was doing.
    let pool = stateful(4);
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");
    pool.release(handle, 1).expect("releases");

    let again = pool.acquire(Some("c1"), 2).expect("acquires");
    assert_eq!(again, handle, "the conversation did not get its own instance back");
}

#[test]
fn a_stateful_instance_is_not_given_to_another_conversation() {
    // The mistake this policy exists to prevent: round-robin would silently lose the plugin's state and the
    // symptom would be a plugin that works when only one thing is happening.
    let pool = stateful(4);
    let first = pool.acquire(Some("c1"), 0).expect("acquires");
    pool.release(first, 1).expect("releases");

    let second = pool.acquire(Some("c2"), 2).expect("acquires");
    assert_ne!(second, first);
    assert_eq!(pool.live(), 2);
}

#[test]
fn a_stateful_pool_at_its_quota_refuses_rather_than_sharing() {
    // A stateful caller cannot make progress by waiting for someone else's instance, so it is told that rather
    // than being given a wait it would spend in vain.
    let pool = stateful(1);
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");
    pool.release(handle, 1).expect("releases");

    match pool.acquire(Some("c2"), 2) {
        Err(PoolRefusal::NoAffinity { conversation, live, limit }) => {
            assert_eq!(conversation, "c2");
            assert_eq!(live, 1);
            assert_eq!(limit, 1);
        }
        other => panic!("expected a no-affinity refusal, got {other:?}"),
    }
    // And it does not claim that waiting would help.
    assert!(!PoolRefusal::NoAffinity {
        conversation: "c".to_owned(),
        live: 1,
        limit: 1
    }
    .is_retryable());
}

#[test]
fn ending_a_conversation_frees_its_instance_for_another() {
    let pool = stateful(1);
    let first = pool.acquire(Some("c1"), 0).expect("acquires");
    pool.release(first, 1).expect("releases");

    assert_eq!(pool.end_conversation("c1"), Some(first));
    assert_eq!(pool.live(), 0);
    assert!(pool.acquire(Some("c2"), 2).is_ok());
}

#[test]
fn ending_a_busy_conversation_does_not_free_its_instance() {
    // A call in progress is still using the instance, and removing it would leave the call with a handle the pool
    // no longer knows.
    let pool = stateful(2);
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");
    assert_eq!(pool.end_conversation("c1"), None);
    assert_eq!(pool.live(), 1);

    // After the call finishes it can be freed.
    pool.release(handle, 1).expect("releases");
    assert_eq!(pool.end_conversation("c1"), Some(handle));
}

#[test]
fn ending_a_conversation_that_has_no_instance_is_not_an_error() {
    let pool = stateful(2);
    assert_eq!(pool.end_conversation("never-seen"), None);
}

#[test]
fn a_stateful_instance_may_take_the_first_conversation_that_asks() {
    // An instance that has never been used has no state to lose.
    let pool = stateful(1);
    let handle = pool.acquire(None, 0).expect("acquires");
    pool.release(handle, 1).expect("releases");

    let bound = pool.acquire(Some("c1"), 2).expect("acquires");
    assert_eq!(bound, handle);
    assert_eq!(pool.report().conversations, vec!["c1".to_owned()]);
}

#[test]
fn a_bound_stateful_instance_is_not_handed_to_a_caller_with_no_conversation() {
    // A caller that does not say which conversation it is would be given an instance carrying someone else's state.
    let pool = stateful(2);
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");
    pool.release(handle, 1).expect("releases");

    let other = pool.acquire(None, 2).expect("acquires");
    assert_ne!(other, handle, "an unbound caller got a bound instance");
}

#[test]
fn a_stateful_instance_is_not_recycled_by_its_call_budget() {
    // Recycling it mid-conversation would lose its state, which is the only thing the policy is about.
    let pool = stateful(1).with_recycling(2, Duration::from_secs(300));
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");
    for at in 1..10 {
        pool.release(handle, at).expect("releases");
    }
    assert_eq!(pool.live(), 1, "a stateful instance was recycled by its call count");
}
