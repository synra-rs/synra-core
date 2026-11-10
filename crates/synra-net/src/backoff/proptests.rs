use core::time::Duration;

use proptest::prelude::*;

use synra_protocol::limits::{
    RECONNECT_BACKOFF, RECONNECT_BASE, RECONNECT_JITTER_PERCENT, RECONNECT_MAX,
};

use super::{Backoff, BackoffRefusal, MAX_ATTEMPTS, RetryTrigger};

proptest! {
    /// Every scheduled delay is within the jitter band of its nominal value, for any seed and any attempt. A
    /// delay outside the band makes the schedule unpredictable in a way the constant does not describe.
    #[test]
    fn a_delay_is_always_within_its_band(seed in any::<u64>(), attempt in 1u32..=MAX_ATTEMPTS) {
        let backoff = Backoff::new(seed);
        let delay = backoff.delay_for(attempt);

        let index = attempt.saturating_sub(1) as usize;
        let nominal = RECONNECT_BACKOFF.get(index).copied().unwrap_or(RECONNECT_BASE).min(RECONNECT_MAX);
        let nominal_ms = nominal.as_millis();
        let span = nominal_ms * u128::from(RECONNECT_JITTER_PERCENT) / 100;

        prop_assert!(delay.as_millis() >= nominal_ms - span, "{:?} below the band", delay);
        prop_assert!(delay.as_millis() <= nominal_ms + span, "{:?} above the band", delay);
        // And never zero, which would be a tight loop.
        prop_assert!(delay > Duration::ZERO);
        prop_assert!(delay <= RECONNECT_MAX);
    }

    /// The schedule is a function of its seed and its attempt count, so the same inputs give the same delay. It
    /// is what makes a failure reproducible from a log line.
    #[test]
    fn the_schedule_is_deterministic(seed in any::<u64>(), attempt in 1u32..=MAX_ATTEMPTS) {
        prop_assert_eq!(Backoff::new(seed).delay_for(attempt), Backoff::new(seed).delay_for(attempt));
    }

    /// The delay never decreases while the short schedule is in force: attempt `n + 1` waits at least as long
    /// as attempt `n` minus the jitter band. A schedule whose early attempts could be longer than its later ones
    /// would let a peer that is refusing connections be hammered.
    #[test]
    fn the_early_schedule_does_not_decrease(seed in any::<u64>()) {
        let backoff = Backoff::new(seed);
        let percent = u128::from(RECONNECT_JITTER_PERCENT);
        for attempt in 1..RECONNECT_BACKOFF.len() as u32 {
            let current = backoff.delay_for(attempt).as_millis();
            let next = backoff.delay_for(attempt + 1).as_millis();
            let current_nominal = RECONNECT_BACKOFF[attempt as usize - 1].as_millis();
            let next_nominal = RECONNECT_BACKOFF[attempt as usize].as_millis();
            // The bands must not overlap: the next nominal less its jitter is above the current nominal plus
            // its jitter.
            prop_assert!(
                next_nominal - next_nominal * percent / 100 >= current_nominal + current_nominal * percent / 100,
                "bands for attempts {} and {} overlap",
                attempt,
                attempt + 1,
            );
            prop_assert!(next >= next_nominal - next_nominal * percent / 100);
            prop_assert!(current <= current_nominal + current_nominal * percent / 100);
        }
    }

    /// The limiter's decision never admits a timer-driven retry before its due time, whatever pair of times it
    /// is given. It is the property that stops a failed connection from becoming a tight loop.
    #[test]
    fn a_timer_never_fires_early(seed in any::<u64>(), failed_at in 0u64..1_000_000, checked_at in 0u64..1_000_000) {
        let mut backoff = Backoff::new(seed);
        let delay = backoff.record_failure(failed_at).expect("schedules");
        let due = failed_at.saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX));

        // A `matches!` with a `{ .. }` pattern cannot be the message of a `prop_assert!`, because proptest
        // builds that message with `format!` and the braces are read as a format argument. So the decision is
        // bound first and asserted as a value.
        let decision = backoff.ready(checked_at, RetryTrigger::Timer);
        if checked_at < due {
            prop_assert!(
                matches!(decision, Err(BackoffRefusal::TooSoon { .. })),
                "admitted {} before its due time {}",
                checked_at,
                due,
            );
        }
        else {
            prop_assert_eq!(decision, Ok(()));
        }
    }
}
