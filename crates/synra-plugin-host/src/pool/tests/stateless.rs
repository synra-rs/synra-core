use super::*;

#[test]
fn a_stateless_pool_creates_an_instance_on_demand() {
    // A pool does not pre-create instances: a plugin that is never called should cost nothing.
    let pool = stateless(4);
    assert_eq!(pool.live(), 0);

    let handle = pool.acquire(None, 0).expect("acquires");
    assert_eq!(pool.live(), 1);
    assert_eq!(pool.busy(), 1);
    assert!(handle > 0);
}

#[test]
fn a_released_instance_is_reused_before_a_new_one_is_made() {
    // An instance that already exists costs nothing more, and creating one per call would make the quota the only
    // thing limiting memory.
    let pool = stateless(4);
    let first = pool.acquire(None, 0).expect("acquires");
    pool.release(first, 1).expect("releases");

    let second = pool.acquire(None, 2).expect("acquires");
    assert_eq!(second, first, "a new instance was made while one was free");
    assert_eq!(pool.live(), 1);
}

#[test]
fn a_busy_instance_is_not_handed_to_a_second_call() {
    let pool = stateless(4);
    let first = pool.acquire(None, 0).expect("acquires");
    let second = pool.acquire(None, 0).expect("acquires");
    assert_ne!(first, second);
    assert_eq!(pool.live(), 2);
    assert_eq!(pool.busy(), 2);
}

#[test]
fn a_stateless_pool_stops_creating_at_its_quota() {
    // The quota is what makes the pool a bound on memory rather than a suggestion.
    let pool = stateless(2);
    let _a = pool.acquire(None, 0).expect("acquires");
    let _b = pool.acquire(None, 0).expect("acquires");

    match pool.acquire(None, 0) {
        Err(PoolRefusal::Exhausted { limit, retry_after_ms }) => {
            assert_eq!(limit, 2);
            assert!(retry_after_ms > 0);
        }
        other => panic!("expected exhaustion, got {other:?}"),
    }
    assert_eq!(pool.live(), 2, "the pool grew past its quota");
}

#[test]
fn an_exhausted_stateless_pool_says_waiting_would_help() {
    // The refusal a caller waits on, as opposed to the one it cannot.
    let pool = stateless(1);
    let handle = pool.acquire(None, 0).expect("acquires");
    let refusal = pool.acquire(None, 0).expect_err("refused");
    assert!(refusal.is_retryable());

    pool.release(handle, 1).expect("releases");
    assert!(pool.acquire(None, 2).is_ok(), "waiting did not help");
}

#[test]
fn a_stateless_instance_is_recycled_after_its_call_budget() {
    // A Wasm instance accumulates whatever the plugin's allocator does not return, and the count bounds that in a
    // way the plugin cannot influence.
    let pool = stateless(1).with_recycling(3, Duration::from_secs(300));
    let handle = pool.acquire(None, 0).expect("acquires");
    pool.release(handle, 1).expect("releases");
    pool.release(handle, 2).expect("releases");
    assert_eq!(pool.live(), 1, "recycled too early");

    pool.release(handle, 3).expect("releases");
    assert_eq!(pool.live(), 0, "the instance was not recycled at its budget");

    // And a new call gets a new handle, not the recycled one.
    let next = pool.acquire(None, 4).expect("acquires");
    assert_ne!(next, handle);
}

#[test]
fn a_stateless_instance_may_serve_any_conversation() {
    // Memory does not persist between calls, so there is nothing to lose by sharing.
    let pool = stateless(1);
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");
    pool.release(handle, 1).expect("releases");
    let again = pool.acquire(Some("c2"), 2).expect("acquires");
    assert_eq!(again, handle);
}
