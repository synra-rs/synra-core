//! The quota module's property tests.

use super::*;
use proptest::prelude::*;
use super::in_window;

use core::time::Duration;

proptest! {
    /// A bucket never holds more than its capacity, whatever sequence of times and amounts it is given. A bucket
    /// that accumulated while a plugin was idle would let it release a whole minute's worth of events at once.
    #[test]
    fn a_bucket_never_exceeds_its_capacity(
        rate in 0u32..1_000,
        burst in 1u32..100,
        steps in proptest::collection::vec((0u64..10_000, 0u32..50), 0..60),
    ) {
        let mut bucket = TokenBucket::new(rate, burst, 0);
        for (at, count) in steps {
            let _ = bucket.try_consume(count, at);
            prop_assert!(
                bucket.available() <= u64::from(burst),
                "held {} of a capacity of {}",
                bucket.available(),
                burst,
            );
        }
    }

    /// Consuming never increases what is available, except by the refill that time passing earns. A bucket that
    /// gained tokens when it was asked for them would be a limit that does not limit.
    #[test]
    fn consuming_at_the_same_instant_never_adds_tokens(
        rate in 0u32..100,
        burst in 1u32..10,
        counts in proptest::collection::vec(0u32..5, 1..30),
    ) {
        let mut bucket = TokenBucket::new(rate, burst, 0);
        let mut previous = bucket.available();
        for count in counts {
            let _ = bucket.try_consume(count, 0);
            let now = bucket.available();
            prop_assert!(now <= previous, "{} rose to {} at the same instant", previous, now);
            previous = now;
        }
    }

    /// A refusal always states a positive wait, so a caller retrying on it makes progress rather than spinning.
    #[test]
    fn a_refusal_always_says_when(
        rate in 1u32..1_000,
        burst in 1u32..10,
        count in 1u32..10,
    ) {
        let mut bucket = TokenBucket::new(rate, burst, 0);
        // Empty it.
        let _ = bucket.try_consume(burst, 0);
        if let Err(refusal) = bucket.try_consume(count, 0) {
            prop_assert!(refusal.retry_after_ms > 0);
            prop_assert!(refusal.shortfall > 0);
            prop_assert!(refusal.retry_after() > Duration::ZERO);
        }
    }

    /// Health never moves backwards past faulted and never skips a rung on the way up: a plugin is not disabled
    /// for a single bad window.
    #[test]
    fn health_never_skips_to_faulted(
        burst in 1u32..3,
        windows in proptest::collection::vec(0u32..PERSISTENT_REFUSALS, 1..20),
    ) {
        let budget = Budget::new(Quota { host_calls_burst: burst, host_calls_per_sec: 1, ..Quota::default() });
        let _ = budget.consume(RateKind::HostCalls, burst, 0);

        let mut seen_faulted = false;
        let mut seen_degraded = false;
        let mut at = 0u64;
        for refusals in windows {
            for _ in 0..refusals {
                let _ = budget.consume(RateKind::HostCalls, 1, at);
            }
            at = in_window(window_number(at) + 1);
            // Close the window.
            let _ = budget.consume(RateKind::HostCalls, 0, at);

            match budget.health() {
                Health::Faulted => {
                    // Reaching faulted requires having been degraded, which requires having been overreaching.
                    prop_assert!(seen_degraded, "faulted without ever being degraded");
                    seen_faulted = true;
                }
                Health::Degraded => seen_degraded = true,
                _ => {}
            }
            if seen_faulted {
                break;
            }
        }
    }

    /// A degraded quota is never larger than the full one, for any field that is halved. A degradation that
    /// raised a limit would be a reward for misbehaving.
    #[test]
    fn a_degraded_quota_is_never_larger(
        memory in 1u64..u64::MAX,
        instances in 1u32..1_000,
        calls in 1u32..10_000,
        events in 1u32..10_000,
    ) {
        let quota = Quota {
            max_memory_bytes: memory,
            max_instances: instances,
            host_calls_per_sec: calls,
            events_per_sec: events,
            ..Quota::default()
        };
        let reduced = quota.degraded();

        prop_assert!(reduced.max_memory_bytes <= quota.max_memory_bytes);
        prop_assert!(reduced.max_instances <= quota.max_instances);
        prop_assert!(reduced.host_calls_per_sec <= quota.host_calls_per_sec);
        prop_assert!(reduced.events_per_sec <= quota.events_per_sec);
        prop_assert!(reduced.call_timeout_ms == quota.call_timeout_ms);
    }
}
