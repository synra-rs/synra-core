use super::*;

#[test]
fn a_stopped_pool_refuses_and_drops_its_instances() {
    // A stopped plugin's instances hold memory and state that no longer correspond to anything the plugin will be
    // asked about.
    let pool = stateless(4);
    let _handle = pool.acquire(None, 0).expect("acquires");
    pool.stop();
    assert!(!pool.is_running());
    assert_eq!(pool.live(), 0);

    assert!(matches!(pool.acquire(None, 1), Err(PoolRefusal::NotRunning)));
    // And starting it again works.
    pool.start();
    assert!(pool.acquire(None, 2).is_ok());
}

#[test]
fn releasing_a_handle_this_pool_never_issued_is_refused() {
    // A handle from a previous pool, or from a different plugin, would otherwise be released twice or released
    // into the wrong pool.
    let pool = stateless(4);
    assert!(matches!(
        pool.release(9_999, 0),
        Err(PoolRefusal::UnknownInstance { handle: 9_999 })
    ));
}

#[test]
fn releasing_twice_does_not_double_count_or_over_recycle() {
    let pool = stateless(1).with_recycling(3, Duration::from_secs(300));
    let handle = pool.acquire(None, 0).expect("acquires");
    pool.release(handle, 1).expect("releases");
    pool.release(handle, 1).expect("releases again");
    // Two releases, so the count is two and the instance is still live.
    assert_eq!(pool.live(), 1);
    assert_eq!(pool.report().total_calls, 2);
}

#[test]
fn handles_are_never_reused_within_a_pool() {
    // A reused handle would make a stale release hit an unrelated instance, which is a defect that surfaces as a
    // plugin whose state appears to jump between conversations.
    // One at a time, so the pool never reaches its limit — the limit is what would stop a new handle being
    // issued, and this test is about the counter, not the bound.
    let pool = stateless(1).with_recycling(1, Duration::ZERO);
    let mut seen = std::collections::HashSet::new();
    for at in 0..20u64 {
        let handle = pool.acquire(None, at).expect("acquires");
        assert!(seen.insert(handle), "handle {handle} was issued twice");
        // Recycling after one call means each iteration gets a genuinely new instance rather than the reused one.
        pool.release(handle, at).expect("releases");
    }
}

#[test]
fn an_idle_instance_is_evicted() {
    // Long enough that a plugin used intermittently keeps its compiled instance, short enough that a plugin
    // nobody is using stops holding memory.
    let pool = stateless(4).with_recycling(1_000, Duration::from_millis(100));
    let handle = pool.acquire(None, 0).expect("acquires");
    pool.release(handle, 0).expect("releases");

    assert!(pool.evict_idle(50).is_empty(), "evicted too early");
    assert_eq!(pool.evict_idle(100), vec![handle]);
    assert_eq!(pool.live(), 0);
}

#[test]
fn a_busy_instance_is_never_evicted() {
    // A long-running call would otherwise be cut off by the sweep, which reads as a plugin crashing.
    let pool = stateless(4).with_recycling(1_000, Duration::from_millis(100));
    let _handle = pool.acquire(None, 0).expect("acquires");

    assert!(pool.evict_idle(1_000_000).is_empty(), "a busy instance was evicted");
    assert_eq!(pool.live(), 1);
}

#[test]
fn an_eviction_does_not_release_a_handle_twice() {
    let pool = stateless(4).with_recycling(1_000, Duration::from_millis(100));
    let handle = pool.acquire(None, 0).expect("acquires");
    pool.release(handle, 0).expect("releases");
    assert_eq!(pool.evict_idle(100), vec![handle]);

    // The swept handle is no longer the pool's, so releasing it is refused rather than creating a phantom record.
    assert!(matches!(pool.release(handle, 101), Err(PoolRefusal::UnknownInstance { .. })));
}

#[test]
fn the_report_carries_what_the_interface_needs() {
    let pool = stateful(4);
    let handle = pool.acquire(Some("c1"), 0).expect("acquires");

    let report = pool.report();
    assert_eq!(report.policy, "stateful");
    assert_eq!(report.limit, 4);
    assert_eq!(report.live, 1);
    assert_eq!(report.busy, 1);
    assert_eq!(report.conversations, vec!["c1".to_owned()]);
    assert_eq!(report.total_calls, 0);

    pool.release(handle, 1).expect("releases");
    assert_eq!(pool.report().total_calls, 1);
}

#[test]
fn the_report_names_the_policy_for_each() {
    assert_eq!(stateless(1).report().policy, "stateless");
    assert_eq!(stateful(1).report().policy, "stateful");
}

#[test]
fn only_the_stateless_policy_shares_instance() {
    assert!(InstancePolicy::Stateless.allows_sharing());
    assert!(!InstancePolicy::Stateful.allows_sharing());
}

#[test]
fn the_policy_and_limits_are_readable() {
    let pool = stateless(7).with_retry_hint(Duration::from_millis(25));
    assert_eq!(pool.policy(), InstancePolicy::Stateless);
    assert_eq!(pool.limit(), 7);
    assert!(pool.is_running());
}

#[test]
fn a_pool_survives_being_asked_for_more_than_its_quota_repeatedly() {
    // A caller in a retry loop must not be able to grow the pool by asking.
    let pool = stateless(2);
    let _a = pool.acquire(None, 0).expect("acquires");
    let _b = pool.acquire(None, 0).expect("acquires");
    for _ in 0..100 {
        let _ = pool.acquire(None, 0);
    }
    assert_eq!(pool.live(), 2);
}

#[test]
fn a_quota_of_zero_refuses_immediately() {
    // A configuration that allows no instances must refuse rather than create one anyway.
    let pool = stateless(0);
    assert!(matches!(pool.acquire(None, 0), Err(PoolRefusal::Exhausted { limit: 0, .. })));
    assert_eq!(pool.live(), 0);
}

#[test]
fn a_pool_report_survives_a_round_trip() {
    let pool = stateful(4);
    let _handle = pool.acquire(Some("c1"), 0).expect("acquires");
    let report = pool.report();

    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("conversations"), "{json}");
    let back: PoolReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

#[test]
fn pool_refusals_explain_themselves() {
    let refusals = [
        PoolRefusal::Exhausted { limit: 2, retry_after_ms: 50 },
        PoolRefusal::NoAffinity { conversation: "c".to_owned(), live: 1, limit: 1 },
        PoolRefusal::NotRunning,
        PoolRefusal::UnknownInstance { handle: 7 },
    ];
    for refusal in refusals {
        let text = refusal.to_string();
        assert!(text.len() > 15, "{refusal:?} -> {text}");
        assert!(!text.contains('{'), "{refusal:?} -> {text}");
    }
}
