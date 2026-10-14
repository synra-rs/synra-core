//! The quota module's tests.

use super::*;



use core::time::Duration;

fn budget() -> Budget {
    Budget::new(Quota::default())
}

/// A budget whose host-call bucket never refills, so every call after the burst is refused.
///
/// Written as a named helper because the tests below are all about the escalation ladder, and a rate that refilled
/// between calls would make them about the token bucket instead: with a default refill of 500 per second, eleven
/// milliseconds of "elapsed" time is a whole token back, and the ladder would never move.
fn refusal_budget() -> Budget {
    Budget::new(Quota { host_calls_burst: 1, host_calls_per_sec: 0, ..Quota::default() })
}

/// The quota `refusal_budget` was built from, for asserting what is in force.
fn refusal_quota() -> Quota {
    Quota { host_calls_burst: 1, host_calls_per_sec: 0, ..Quota::default() }
}

// ── Token buckets ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_new_bucket_is_full() {
    // A plugin that just started should not be throttled before it has done anything.
    let bucket = TokenBucket::new(100, 200, 0);
    assert_eq!(bucket.available(), 200);
    assert_eq!(bucket.capacity(), 200);
}

#[test]
fn taking_tokens_reduces_what_is_available() {
    let mut bucket = TokenBucket::new(100, 200, 0);
    assert_eq!(bucket.try_consume(50, 0), Ok(()));
    assert_eq!(bucket.available(), 150);
}

#[test]
fn a_bucket_refills_continuously_rather_than_in_ticks() {
    // A tick-based bucket gives a plugin nothing for the rest of the second after it exhausts one, which turns a
    // burst into a stall and makes the observed rate depend on where in the second the burst started.
    let mut bucket = TokenBucket::new(100, 1, 0);
    assert_eq!(bucket.try_consume(1, 0), Ok(()));
    assert_eq!(bucket.available(), 0);

    // Ten milliseconds later, one token's worth has accumulated.
    assert_eq!(bucket.try_consume(1, 10), Ok(()));
    // And again.
    assert_eq!(bucket.try_consume(1, 20), Ok(()));
}

#[test]
fn an_exhausted_bucket_says_how_long_to_wait() {
    let mut bucket = TokenBucket::new(10, 1, 0);
    assert_eq!(bucket.try_consume(1, 0), Ok(()));

    match bucket.try_consume(1, 0) {
        Err(refusal) => {
            // Ten per second means one token per 100 ms.
            assert_eq!(refusal.retry_after_ms, 100);
            assert_eq!(refusal.shortfall, TokenBucket::SCALE);
        }
        Ok(()) => panic!("the bucket should be empty"),
    }
}

#[test]
fn a_bucket_never_fills_past_its_capacity() {
    // A bucket that accumulated while a plugin was idle would let it release a whole minute's worth of events at
    // once, which is the burst the capacity exists to bound.
    let mut bucket = TokenBucket::new(100, 10, 0);
    let _ = bucket.try_consume(10, 0);
    assert_eq!(bucket.available(), 0);

    // An hour later it is still only as full as its capacity.
    bucket.try_consume(0, 3_600_000).expect("zero costs nothing");
    assert_eq!(bucket.available(), 10);
}

#[test]
fn a_clock_that_moves_backwards_does_not_remove_tokens() {
    // A bucket that lost tokens on a backwards reading would refuse a call it had already earned.
    let mut bucket = TokenBucket::new(100, 200, 1_000);
    assert_eq!(bucket.try_consume(100, 1_000), Ok(()));
    let after = bucket.available();

    // A refill at an earlier time adds nothing and takes nothing.
    assert_eq!(bucket.try_consume(0, 500), Ok(()));
    assert_eq!(bucket.available(), after);
}

#[test]
fn a_bucket_with_no_refill_waits_forever_rather_than_dividing_by_zero() {
    // A caller showing this says "not for a very long time" rather than hanging on an arithmetic error.
    let mut bucket = TokenBucket::new(0, 1, 0);
    assert_eq!(bucket.try_consume(1, 0), Ok(()));
    match bucket.try_consume(1, 0) {
        Err(refusal) => assert_eq!(refusal.retry_after_ms, u64::MAX),
        Ok(()) => panic!("the bucket should be empty"),
    }
}

#[test]
fn refilling_fully_resets_a_bucket() {
    let mut bucket = TokenBucket::new(10, 100, 0);
    assert_eq!(bucket.try_consume(100, 0), Ok(()));
    assert_eq!(bucket.available(), 0);

    bucket.refill_fully(500);
    assert_eq!(bucket.available(), 100);
}

#[test]
fn consuming_more_than_the_capacity_is_refused() {
    // A single call that asks for more tokens than the bucket can ever hold would otherwise be admitted once and
    // then wedge the bucket at zero forever.
    let mut bucket = TokenBucket::new(100, 10, 0);
    assert!(bucket.try_consume(11, 0).is_err());
    // The bucket is untouched.
    assert_eq!(bucket.available(), 10);
}

// ── Static limits ─────────────────────────────────────────────────────────────────────────────

#[test]
fn static_limits_are_checked_against_the_defaults() {
    let budget = budget();
    assert_eq!(budget.check_memory(32 * 1024 * 1024), Ok(()));
    assert_eq!(budget.check_instances(4), Ok(()));
    assert_eq!(budget.check_storage(1024), Ok(()));
    assert_eq!(budget.check_transfers(4), Ok(()));
}

#[test]
fn exceeding_a_static_limit_names_it_and_the_amount() {
    let budget = budget();
    match budget.check_memory(u64::MAX) {
        Err(StaticRefusal::Memory { limit, .. }) => assert_eq!(limit, Quota::default().max_memory_bytes),
        other => panic!("expected a memory refusal, got {other:?}"),
    }
    match budget.check_instances(100) {
        Err(StaticRefusal::Instances { wanted, limit }) => {
            assert_eq!(wanted, 100);
            assert_eq!(limit, 4);
        }
        other => panic!("expected an instance refusal, got {other:?}"),
    }
    assert!(matches!(budget.check_storage(u64::MAX), Err(StaticRefusal::Storage { .. })));
    assert!(matches!(budget.check_transfers(99), Err(StaticRefusal::Transfers { .. })));
}

#[test]
fn a_static_refusal_is_never_retryable() {
    // A static limit is a decision about how much a plugin may hold, so retrying against it is retrying against
    // the host's own configuration.
    let refusals = [
        StaticRefusal::Memory { wanted: 2, limit: 1 },
        StaticRefusal::Instances { wanted: 2, limit: 1 },
        StaticRefusal::Storage { wanted: 2, limit: 1 },
        StaticRefusal::Transfers { wanted: 2, limit: 1 },
    ];
    for refusal in refusals {
        assert!(!refusal.is_retryable(), "{refusal:?}");
        assert!(!refusal.to_string().is_empty(), "{refusal:?}");
    }
}

// ── Rates ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_burst_within_the_allowance_is_admitted() {
    let budget = budget();
    // The host-call burst is a thousand, so a hundred calls at the same instant are fine.
    for _ in 0..100 {
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    }
    assert_eq!(budget.admitted(), 100);
    assert_eq!(budget.refused(), 0);
}

#[test]
fn exceeding_the_burst_is_refused_and_recorded() {
    let budget = Budget::new(Quota { host_calls_burst: 2, host_calls_per_sec: 1, ..Quota::default() });
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));

    match budget.consume(RateKind::HostCalls, 1, 0) {
        Err(refusal) => assert_eq!(refusal.kind, Some(RateKind::HostCalls)),
        Ok(()) => panic!("the bucket should be empty"),
    }
    assert_eq!(budget.refused(), 1);
}

#[test]
fn each_kind_has_its_own_bucket() {
    // A plugin that emits a thousand events should not thereby be unable to read a file.
    let budget = Budget::new(Quota { events_per_sec: 1, fs_ops_per_sec: 100, ..Quota::default() });
    assert_eq!(budget.consume(RateKind::Events, 1, 0), Ok(()));
    assert!(budget.consume(RateKind::Events, 1, 0).is_err());
    // The filesystem bucket is untouched.
    assert_eq!(budget.consume(RateKind::FsOps, 1, 0), Ok(()));
}

#[test]
fn every_rate_kind_has_a_quota_field() {
    // A kind with no field would have a zero rate and refuse everything, which reads as a broken plugin rather
    // than a missing limit.
    let quota = Quota::default();
    for kind in RateKind::ALL {
        let (rate, burst) = quota.rate_for(*kind);
        assert!(rate > 0, "{kind:?} has no rate");
        assert!(burst > 0, "{kind:?} has no burst");
        assert!(!kind.as_str().is_empty(), "{kind:?}");
    }
    // And the list covers every kind, so a new variant cannot be forgotten here.
    assert_eq!(RateKind::ALL.len(), 5);

    // The index is the position in `ALL`, which is what the refusal counts are keyed by. A mismatch would file one
    // kind's refusals under another.
    for (position, kind) in RateKind::ALL.iter().enumerate() {
        assert_eq!(kind.index(), position, "{kind:?}");
    }
}

// ── The escalation ladder ─────────────────────────────────────────────────────────────────────

/// Records enough refusals to fill one window.
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

// ── Reporting ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_report_carries_what_the_settings_screen_needs() {
    let budget = refusal_budget();
    assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
    assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());

    let report = budget.report();
    assert_eq!(report.health, "good");
    assert_eq!(report.admitted, 1);
    assert_eq!(report.refused, 1);
    assert!(!report.explanation.is_empty());
    assert_eq!(
        report
            .refusals_by_kind
            .iter()
            .find(|(kind, _)| kind == "host-calls")
            .map(|(_, count)| *count),
        Some(1)
    );
    assert_eq!(report.quota, refusal_quota());
}

#[test]
fn every_health_level_explains_itself_for_a_user() {
    // A user whose plugin has been degraded needs to know why it got slower.
    for health in [Health::Good, Health::Overreaching, Health::Degraded, Health::Faulted] {
        assert!(health.explain().len() > 15, "{health:?}");
        assert!(!health.as_str().is_empty(), "{health:?}");
    }
}

#[test]
fn the_ladder_is_ordered_from_best_to_worst() {
    // The ordering is what a caller uses to show a trend, and an out-of-order ladder would make a plugin look
    // like it was improving while it got worse.
    assert!(Health::Good < Health::Overreaching);
    assert!(Health::Overreaching < Health::Degraded);
    assert!(Health::Degraded < Health::Faulted);
    // And only the last one stops the plugin.
    assert!(Health::Good.is_running());
    assert!(Health::Overreaching.is_running());
    assert!(Health::Degraded.is_running());
    assert!(!Health::Faulted.is_running());
}

#[test]
fn only_ordinary_health_is_not_worth_mentioning() {
    assert!(!Health::Good.is_worth_telling_the_user());
    assert!(Health::Overreaching.is_worth_telling_the_user());
    assert!(Health::Degraded.is_worth_telling_the_user());
    assert!(Health::Faulted.is_worth_telling_the_user());
}

#[test]
fn a_report_survives_a_round_trip() {
    let budget = Budget::new(Quota::default());
    let report = budget.report();
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("refusalsByKind"), "{json}");
    let back: QuotaReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

#[test]
fn a_quota_survives_a_round_trip() {
    // The quota reaches the interface, so its field names are part of what a user setting a custom quota sees.
    let quota = Quota::default();
    let json = serde_json::to_string(&quota).expect("serialises");
    assert!(json.contains("maxMemoryBytes"), "{json}");
    assert!(json.contains("callTimeoutMs"), "{json}");
    let back: Quota = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, quota);
}

#[test]
fn a_limited_refusal_reports_its_wait() {
    let refusal = RateLimited { kind: Some(RateKind::Events), retry_after_ms: 250, shortfall: 1_000 };
    assert_eq!(refusal.retry_after(), Duration::from_millis(250));
    assert!(refusal.to_string().contains("250"));
}
