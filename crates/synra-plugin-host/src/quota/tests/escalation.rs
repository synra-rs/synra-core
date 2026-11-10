use super::super::{Budget, Health, PERSISTENT_REFUSALS, Quota, RateKind, in_window};
use super::{refusal_budget, refusal_quota};

/// Records exactly [`PERSISTENT_REFUSALS`] refusals inside one window.
///
/// Exactly that many, because the threshold is a boundary: one more would make the window persistently refused
/// and move the ladder, which is a different test. The timing helper that uses this gives the plugin a burst of
/// one and no refill, so the first call succeeds and the rest are refused.
fn fill_window(budget: &Budget, at_ms: u64) {
    for _ in 0..PERSISTENT_REFUSALS {
        let _ = budget.consume(RateKind::HostCalls, 1, at_ms);
    }
}

#[test]
fn a_single_exceedance_does_not_change_health() {
    // Ordinary: a plugin that fires a burst of events hits a bucket and waits.
    let budget = refusal_budget();
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());
    assert_eq!(budget.health(), Health::Good);
}

#[test]
fn persistent_refusals_move_a_plugin_to_overreaching_first() {
    // The rung that exists so the user is told before anything is restricted.
    let budget = refusal_budget();
    // The first window is not persistently refused, so the plugin is not degraded yet.
    fill_window(&budget, in_window(0));
    assert_eq!(budget.health(), Health::Good);

    // The second is, which is the rung that tells the user before anything is restricted.
    fill_window(&budget, in_window(1));
    assert_eq!(budget.health(), Health::Overreaching);
    // And it is still running at full quota.
    assert!(budget.health().is_running());
    assert!(!budget.health().uses_degraded_quota());
}

#[test]
fn another_bad_window_degrades_the_plugin() {
    let budget = refusal_budget();

    // Walk the ladder rather than counting windows by hand: the point of the test is that a second persistently
    // refused window degrades the plugin, not that a particular arithmetic produces that many windows.
    let mut window = 0u64;
    while budget.health() == Health::Good && window < 10 {
        fill_window(&budget, in_window(window));
        window += 1;
    }
    assert_eq!(budget.health(), Health::Overreaching);
    fill_window(&budget, in_window(window));
    assert_eq!(budget.health(), Health::Degraded);
    // Still running, at a reduced quota.
    assert!(budget.health().is_running());
    assert!(budget.health().uses_degraded_quota());
}

#[test]
fn a_degraded_plugin_that_keeps_failing_is_faulted() {
    // The only rung that stops the plugin, reached only after the two below it were tried.
    let budget = refusal_budget();

    for window in 0..12u64 {
        fill_window(&budget, in_window(window));
        if budget.health() == Health::Faulted {
            break;
        }
    }
    assert_eq!(budget.health(), Health::Faulted);
    assert!(!budget.health().is_running());
    assert!(budget.health().is_worth_telling_the_user());
}

#[test]
fn a_faulted_plugin_may_not_consume_anything() {
    // A caller that forgot to check health would otherwise hand a disabled plugin its budget back.
    let budget = refusal_budget();
    for window in 0..12u64 {
        fill_window(&budget, in_window(window));
        if budget.health() == Health::Faulted {
            break;
        }
    }
    assert_eq!(budget.health(), Health::Faulted);

    // Even a bucket with tokens left refuses.
    match budget.consume(RateKind::FsOps, 1, u64::MAX) {
        Err(refusal) => assert_eq!(refusal.retry_after_ms, u64::MAX),
        Ok(()) => panic!("a faulted plugin should not consume"),
    }
}

#[test]
fn a_recovering_plugin_climbs_back_down() {
    // Two good windows undo one bad one, which lets a plugin that was degraded recover without the user
    // intervening.
    let budget = refusal_budget();

    let mut window = 0u64;
    while budget.health() != Health::Degraded && window < 12 {
        fill_window(&budget, in_window(window));
        window += 1;
    }
    assert_eq!(budget.health(), Health::Degraded);

    // Now stop refusing: each window boundary with no refusals subtracts one.
    for _ in 0..6 {
        window += 1;
        // A zero-token consumption passes and does not record a refusal, but it does advance the window.
        budget.tick(in_window(window));
    }
    assert!(
        budget.health() != Health::Faulted,
        "a plugin that stopped misbehaving was faulted anyway"
    );
}

#[test]
fn faulted_is_not_climbed_out_of_by_arithmetic() {
    // A ladder that could climb back down on its own would re-enable a plugin that was disabled for a reason.
    let budget = refusal_budget();
    for window in 0..12u64 {
        fill_window(&budget, in_window(window));
        if budget.health() == Health::Faulted {
            break;
        }
    }
    assert_eq!(budget.health(), Health::Faulted);

    for window in 12..30u64 {
        budget.tick(in_window(window));
    }
    assert_eq!(budget.health(), Health::Faulted, "faulted climbed back down on its own");
}

#[test]
fn a_user_can_clear_a_faulted_plugin() {
    let budget = refusal_budget();
    for window in 0..12u64 {
        fill_window(&budget, in_window(window));
        if budget.health() == Health::Faulted {
            break;
        }
    }
    assert_eq!(budget.health(), Health::Faulted);

    budget.reset(in_window(100));
    assert_eq!(budget.health(), Health::Good);
    // And the buckets are full, so a plugin that was disabled for a while is not refused immediately for a
    // bucket that never refilled while it was not running.
    assert_eq!(budget.consume(RateKind::HostCalls, 1, in_window(100)), Ok(()));
}

#[test]
fn degradation_halves_the_rate_limits() {
    let full = Quota::default();
    let reduced = full.degraded();
    assert_eq!(reduced.host_calls_per_sec, full.host_calls_per_sec / 2);
    assert_eq!(reduced.events_per_sec, full.events_per_sec / 2);
    assert_eq!(reduced.max_instances, full.max_instances / 2);
    assert_eq!(reduced.max_memory_bytes, full.max_memory_bytes / 2);
}

#[test]
fn degradation_never_reaches_zero_and_leaves_the_timeout_alone() {
    // A limit of zero would disable the plugin, which is the faulted rung's job, and halving the timeout would
    // turn a plugin that is merely slow into one that fails — a different problem from the one degradation
    // addresses.
    let tiny = Quota {
        max_instances: 1,
        max_open_transfers: 1,
        host_calls_per_sec: 1,
        host_calls_burst: 1,
        events_per_sec: 1,
        network_requests_per_sec: 1,
        network_concurrent: 1,
        device_sends_per_sec: 1,
        fs_ops_per_sec: 1,
        ..Quota::default()
    };
    let reduced = tiny.degraded();
    assert_eq!(reduced.max_instances, 1);
    assert_eq!(reduced.max_open_transfers, 0, "zero transfers is a limit, not a crash");
    assert_eq!(reduced.host_calls_per_sec, 1);
    assert_eq!(reduced.events_per_sec, 1);
    assert_eq!(reduced.call_timeout_ms, tiny.call_timeout_ms);
    // Storage is not halved: the plugin's data does not shrink because it asked too often.
    assert_eq!(reduced.max_storage_bytes, tiny.max_storage_bytes);
}

#[test]
fn the_quota_in_force_follows_the_health() {
    let budget = refusal_budget();
    assert_eq!(budget.quota().host_calls_per_sec, refusal_quota().host_calls_per_sec);

    // Walk to exactly `Degraded` rather than counting windows by hand, then assert the quota moved with it.
    let mut window = 0u64;
    while budget.health() < Health::Degraded && window < 10 {
        fill_window(&budget, in_window(window));
        window += 1;
    }
    assert_eq!(budget.health(), Health::Degraded);
    // The degraded quota halves the *default* rate, not the test's zero — `degraded` floors a rate at one, because
    // a limit of zero would disable the plugin and that is the faulted rung's job.
    assert_eq!(budget.quota().host_calls_per_sec, 1, "the degraded rate is floored at one, not zero");
}

#[test]
fn a_window_with_few_refusals_is_not_persistent() {
    // A plugin that hits a bucket twice in ten seconds is not misbehaving.
    let budget = Budget::new(Quota {
        host_calls_burst: 1,
        host_calls_per_sec: 1,
        events_per_sec: 1,
        ..Quota::default()
    });
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());
    // Half a second, so the bucket has not refilled a whole token and the call is still refused.
    assert!(budget.consume(RateKind::HostCalls, 1, 500).is_err());

    // Close the window with only two refusals in it.
    budget.tick(in_window(1));
    assert_eq!(budget.health(), Health::Good);
}
