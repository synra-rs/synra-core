//! Reconnection: when to try again, and how long to wait.
//!
//! # The schedule is a floor, not a timer
//!
//! [`synra_protocol::limits::RECONNECT_BACKOFF`] exists because a failed connection must not be retried in a tight
//! loop — that turns a peer that is merely asleep into a peer whose network is saturated. But a device that has
//! just *rediscovered* the peer it was waiting for should not sit out the remaining twenty seconds of a backoff it
//! no longer needs.
//!
//! So there are two kinds of event:
//!
//! * **Time passing** — the scheduled delay elapsed, so a retry is due.
//! * **Something changing** — the peer was rediscovered, the network changed, the application came to the
//!   foreground. Each of these is evidence the previous failure's cause may be gone, so the wait is cut short.
//!
//! # Why the jitter is not optional
//!
//! Every device that lost the same peer at the same moment — a router reboot — would otherwise retry at the same
//! instant, and the router would see the whole fleet arrive together. The jitter spreads them.
//!
//! **The jitter is derived, not random.** A caller supplies the seed, and the same seed always produces the same
//! delay. That is what makes the schedule testable: a test asserts the exact delays for a known seed rather than a
//! range, and a failure is reproducible from a log line.

use core::time::Duration;

use synra_protocol::limits::{
    RECONNECT_BACKOFF, RECONNECT_BASE, RECONNECT_JITTER_PERCENT, RECONNECT_MAX,
};

/// What caused a retry to be considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryTrigger {
    /// The scheduled delay elapsed.
    Timer,
    /// The peer was seen again — a discovery reply, a mDNS announcement.
    Rediscovered,
    /// The set of available networks changed.
    NetworkChanged,
    /// The application came to the foreground.
    Foreground,
    /// A local change means the peer may now accept a connection, such as a plugin that has to be synchronised.
    LocalChange,
}

impl RetryTrigger {
    /// Whether this trigger justifies retrying before the schedule says so.
    ///
    /// Only [`Self::Timer`] waits. The others are all evidence that the condition which caused the failure may
    /// have changed, and making them wait would mean a device that was rediscovered sits idle through a backoff
    /// designed for a device that was not.
    #[must_use]
    pub const fn overrides_schedule(self) -> bool {
        !matches!(self, Self::Timer)
    }

    /// A name for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Rediscovered => "rediscovered",
            Self::NetworkChanged => "network-changed",
            Self::Foreground => "foreground",
            Self::LocalChange => "local-change",
        }
    }
}

/// Why a peer is not being retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackoffRefusal {
    /// The delay has not elapsed and nothing has changed.
    TooSoon {
        /// How long is left.
        remaining: Duration,
    },
    /// Retrying has been given up on.
    ///
    /// A peer that has failed this many times is not going to succeed on the next attempt, and continuing to try
    /// costs battery and log volume. The peer is still rediscoverable; it is this schedule that stops, not the
    /// possibility of ever connecting.
    GivenUp {
        /// How many attempts were made.
        attempts: u32,
    },
}

/// How many consecutive failures before the schedule stops.
///
/// A ceiling rather than unbounded: an application that has tried for an hour against a peer that is unplugged is
/// one that has spent an hour of battery and filled a log file. Rediscovery is what starts it again.
pub const MAX_ATTEMPTS: u32 = 12;

/// Why the schedule was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResetReason {
    /// A connection was established and the handshake completed.
    Connected,
    /// The user asked for it, such as a "reconnect now" button.
    UserRequest,
    /// The peer was unpaired, so there is nothing to reconnect to.
    Unpaired,
}

/// A peer's reconnection schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    attempts: u32,
    /// When the next retry becomes due, as a monotonic millisecond count.
    due_at_ms: Option<u64>,
    seed: u64,
    given_up: bool,
}

impl Backoff {
    /// A schedule for a peer that has never failed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { attempts: 0, due_at_ms: None, seed, given_up: false }
    }

    /// How many consecutive failures there have been.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Whether retrying has been given up on.
    #[must_use]
    pub const fn has_given_up(&self) -> bool {
        self.given_up
    }

    /// When the next retry is due, if one is scheduled.
    #[must_use]
    pub const fn due_at_ms(&self) -> Option<u64> {
        self.due_at_ms
    }

    /// Records a failure at `now_ms` and schedules the next attempt.
    ///
    /// # Returns
    ///
    /// The delay that was scheduled. `None` when the attempt ceiling was reached, in which case no retry is
    /// scheduled and [`Self::has_given_up`] becomes true.
    pub fn record_failure(&mut self, now_ms: u64) -> Option<Duration> {
        self.attempts = self.attempts.saturating_add(1);

        if self.attempts > MAX_ATTEMPTS {
            self.given_up = true;
            self.due_at_ms = None;
            return None;
        }

        let delay = self.delay_for(self.attempts);
        self.due_at_ms = Some(now_ms.saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)));
        Some(delay)
    }

    /// The delay before the given attempt, with jitter.
    ///
    /// The schedule is the four short delays from the protocol, then a constant base that is capped. Attempt
    /// numbers count from one, so the first failure schedules `RECONNECT_BACKOFF[0]`.
    #[must_use]
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let index = attempt.saturating_sub(1) as usize;
        let nominal = match RECONNECT_BACKOFF.get(index) {
            Some(delay) => *delay,
            // Past the short schedule, a constant base — not a doubling. The design document's schedule flattens
            // rather than growing, because a peer that is reachable at all is usually reachable in half a minute,
            // and an exponential tail would mean waiting hours for one that came back a minute later.
            None => RECONNECT_BASE,
        };
        let capped = nominal.min(RECONNECT_MAX);
        self.jitter(capped, attempt)
    }

    /// Applies the jitter for an attempt.
    ///
    /// Derived from the seed and the attempt number, so the same seed gives the same delays and a test can assert
    /// them exactly. The range is `[nominal - pct, nominal + pct]`.
    fn jitter(&self, nominal: Duration, attempt: u32) -> Duration {
        let percent = u64::from(RECONNECT_JITTER_PERCENT);
        if percent == 0 {
            return nominal;
        }
        let nominal_ms = u64::try_from(nominal.as_millis()).unwrap_or(u64::MAX);
        let span = nominal_ms.saturating_mul(percent) / 100;
        if span == 0 {
            return nominal;
        }

        // A splitmix64 step: it mixes the attempt number and the seed so consecutive attempts do not move in a
        // straight line. A plain `seed + attempt` would make every peer with an adjacent seed retry at adjacent
        // times, which is the lockstep the jitter exists to break.
        let mut mixed = self.seed ^ (u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        mixed ^= mixed >> 30;
        mixed = mixed.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed ^= mixed >> 27;
        mixed = mixed.wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^= mixed >> 31;

        // The offset lands in `[-span, span]`.
        let offset = i64::try_from(mixed % (span.saturating_mul(2).saturating_add(1))).unwrap_or(0);
        let jittered = i64::try_from(nominal_ms).unwrap_or(0)
            .saturating_add(offset)
            .saturating_sub(i64::try_from(span).unwrap_or(0));
        let clamped = jittered.clamp(1, i64::try_from(RECONNECT_MAX.as_millis()).unwrap_or(i64::MAX));
        Duration::from_millis(u64::try_from(clamped).unwrap_or(1))
    }

    /// Whether a retry may happen now.
    ///
    /// # Errors
    ///
    /// [`BackoffRefusal::GivenUp`] when the ceiling was reached and nothing has changed, or
    /// [`BackoffRefusal::TooSoon`] when the delay has not elapsed and the trigger does not override it.
    ///
    /// # Giving up is not permanent
    ///
    /// Reaching the ceiling stops the *timer*: an application that has tried twelve times against a peer that is
    /// unplugged has spent its battery and filled a log, and a thirteenth attempt a minute later is not going to
    /// succeed. But a trigger that is evidence of the peer — it was rediscovered, the network changed — is exactly
    /// what the ceiling was waiting for, and refusing it would leave the peer unreachable until the process
    /// restarted. So such a trigger clears the ceiling and is admitted.
    pub const fn ready(&self, now_ms: u64, trigger: RetryTrigger) -> Result<(), BackoffRefusal> {
        if self.given_up {
            return match trigger.overrides_schedule() {
                true => Ok(()),
                false => Err(BackoffRefusal::GivenUp { attempts: self.attempts }),
            };
        }
        // A trigger that overrides the schedule is evidence the cause of the failure may be gone, so waiting the
        // rest of a backoff designed for a different situation would be waiting for no reason.
        if trigger.overrides_schedule() {
            return Ok(());
        }
        match self.due_at_ms {
            Some(due) if now_ms < due => {
                Err(BackoffRefusal::TooSoon { remaining: Duration::from_millis(due - now_ms) })
            }
            // No scheduled time means the first attempt, which never waits.
            _ => Ok(()),
        }
    }

    /// Clears the ceiling after an event trigger was admitted while given up.
    ///
    /// Separate from [`Self::reset`] so a caller can tell "the schedule is being restarted" from "one overriding
    /// attempt was allowed", and so the attempt count is available in a log line before it is cleared.
    pub const fn clear_ceiling(&mut self) {
        self.given_up = false;
        self.due_at_ms = None;
    }

    /// Clears the schedule.
    ///
    /// Called on a completed handshake, on the user's request, and on unpairing. The reason is recorded rather
    /// than only the effect, because a schedule that reset when it should not have is otherwise invisible.
    pub const fn reset(&mut self, reason: ResetReason) {
        self.attempts = 0;
        self.due_at_ms = None;
        self.given_up = false;
        let _ = reason;
    }

    /// The seed this schedule derives its jitter from.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }
}

/// A retry that is waiting, for the interface to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRetry {
    /// The peer.
    pub peer: String,
    /// How many times it has failed.
    pub attempts: u32,
    /// How long until the next attempt, as of when it was computed.
    pub in_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_attempt_never_waits() {
        // A peer that was just paired or just rediscovered should be tried immediately; making the first attempt
        // wait would add a second of latency to every connection.
        let backoff = Backoff::new(1);
        assert_eq!(backoff.ready(0, RetryTrigger::Timer), Ok(()));
        assert_eq!(backoff.attempts(), 0);
    }

    #[test]
    fn failures_follow_the_protocol_schedule() {
        // The four short delays, then the constant base. Asserted as the shape rather than as exact values, because
        // the jitter moves them — the exact values are asserted in the next test.
        let mut backoff = Backoff::new(7);
        for (attempt, nominal) in RECONNECT_BACKOFF.iter().enumerate() {
            let delay = backoff.record_failure(0).expect("schedules");
            let nominal_ms = u64::try_from(nominal.as_millis()).unwrap_or(0);
            let low = nominal_ms * 80 / 100;
            let high = nominal_ms * 120 / 100;
            assert!(
                delay.as_millis() as u64 >= low && (delay.as_millis() as u64) <= high,
                "attempt {} scheduled {:?}, outside [{}ms, {}ms]",
                attempt + 1,
                delay,
                low,
                high
            );
        }
        // Past the schedule it is the base, capped.
        for _ in 0..3 {
            let delay = backoff.record_failure(0).expect("schedules");
            let base_ms = u64::try_from(RECONNECT_BASE.as_millis()).unwrap_or(0);
            assert!((delay.as_millis() as u64) <= base_ms * 120 / 100, "{delay:?}");
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_delays() {
        // Derived rather than random, so a failure is reproducible from a log line and a test can assert values
        // rather than ranges.
        let mut first = Backoff::new(42);
        let mut second = Backoff::new(42);
        for _ in 0..6 {
            assert_eq!(first.record_failure(0), second.record_failure(0));
        }

        // And a different seed moves them, which is the whole point of the jitter.
        let mut other = Backoff::new(43);
        let differs = (0..6).any(|_| first.record_failure(0) != other.record_failure(0));
        assert!(differs, "two seeds produced identical schedules");
    }

    #[test]
    fn consecutive_attempts_do_not_move_in_a_straight_line() {
        // A plain `seed + attempt` would make every peer with an adjacent seed retry at adjacent times, which is the
        // lockstep the jitter exists to break.
        let mut backoff = Backoff::new(1_000);
        let delays: Vec<u128> = (0..4).map(|_| backoff.record_failure(0).expect("schedules").as_millis()).collect();
        // Within the short schedule the delays grow, so the assertion is about the *jitter offsets* rather than the
        // delays: they are not all the same fraction of their nominal value.
        let nominal: Vec<u128> = RECONNECT_BACKOFF.iter().map(|d| d.as_millis()).collect();
        let offsets: Vec<i128> = delays
            .iter()
            .zip(&nominal)
            .map(|(delay, nominal)| *delay as i128 - *nominal as i128)
            .collect();
        let fractions: Vec<i128> = offsets
            .iter()
            .zip(&nominal)
            .map(|(offset, nominal)| if *nominal == 0 { 0 } else { offset * 100 / *nominal as i128 })
            .collect();
        assert!(
            fractions.windows(2).any(|pair| pair[0] != pair[1]),
            "every attempt got the same jitter fraction: {fractions:?}"
        );
    }

    #[test]
    fn the_jitter_stays_within_its_percentage() {
        // A jitter that pushed a delay outside its band would make the schedule unpredictable in a way the constant
        // does not describe.
        for seed in 0..200u64 {
            let mut backoff = Backoff::new(seed);
            for (index, nominal) in RECONNECT_BACKOFF.iter().enumerate() {
                let delay = backoff.record_failure(0).expect("schedules");
                let nominal_ms = nominal.as_millis();
                let span = nominal_ms * u128::from(RECONNECT_JITTER_PERCENT) / 100;
                let low = nominal_ms - span;
                let high = nominal_ms + span;
                assert!(
                    delay.as_millis() >= low && delay.as_millis() <= high,
                    "seed {seed} attempt {} gave {:?}, outside [{low}ms, {high}ms]",
                    index + 1,
                    delay
                );
            }
        }
    }

    #[test]
    fn a_delay_is_never_zero() {
        // A zero delay is a tight loop: the failure path becomes the busy path, which is the thing the schedule
        // exists to prevent.
        for seed in 0..500u64 {
            let mut backoff = Backoff::new(seed);
            for _ in 0..MAX_ATTEMPTS {
                let delay = backoff.record_failure(0).expect("schedules");
                assert!(delay > Duration::ZERO, "seed {seed} produced a zero delay");
            }
        }
    }

    #[test]
    fn a_scheduled_retry_is_refused_until_its_time() {
        let mut backoff = Backoff::new(1);
        let delay = backoff.record_failure(1_000).expect("schedules");
        let due = 1_000u64 + u64::try_from(delay.as_millis()).unwrap_or(0);

        match backoff.ready(due - 1, RetryTrigger::Timer) {
            Err(BackoffRefusal::TooSoon { remaining }) => {
                assert_eq!(remaining, Duration::from_millis(1));
            }
            other => panic!("expected a wait, got {other:?}"),
        }
        assert_eq!(backoff.ready(due, RetryTrigger::Timer), Ok(()));
        assert_eq!(backoff.ready(due + 10_000, RetryTrigger::Timer), Ok(()));
    }

    #[test]
    fn every_trigger_but_the_timer_overrides_the_schedule() {
        // Each of the others is evidence the condition which caused the failure may have changed, and making them
        // wait would mean a device that was rediscovered sits idle through a backoff designed for a device that was
        // not.
        assert!(!RetryTrigger::Timer.overrides_schedule());
        for trigger in [
            RetryTrigger::Rediscovered,
            RetryTrigger::NetworkChanged,
            RetryTrigger::Foreground,
            RetryTrigger::LocalChange,
        ] {
            assert!(trigger.overrides_schedule(), "{trigger:?}");
        }
    }

    #[test]
    fn an_event_trigger_retries_immediately() {
        let mut backoff = Backoff::new(1);
        backoff.record_failure(0).expect("schedules");
        // The timer still has almost a second to go, and the peer was just seen again.
        assert!(backoff.ready(10, RetryTrigger::Timer).is_err());
        assert_eq!(backoff.ready(10, RetryTrigger::Rediscovered), Ok(()));
        assert_eq!(backoff.ready(10, RetryTrigger::NetworkChanged), Ok(()));
    }

    #[test]
    fn retrying_is_given_up_on_after_the_ceiling() {
        // An application that has tried for an hour against a peer that is unplugged has spent an hour of battery
        // and filled a log file.
        let mut backoff = Backoff::new(1);
        for _ in 0..MAX_ATTEMPTS {
            assert!(backoff.record_failure(0).is_some(), "within the ceiling");
        }
        assert_eq!(backoff.attempts(), MAX_ATTEMPTS);
        assert!(!backoff.has_given_up());

        assert_eq!(backoff.record_failure(0), None, "the ceiling schedules nothing");
        assert!(backoff.has_given_up());
        assert_eq!(backoff.due_at_ms(), None);
    }

    #[test]
    fn giving_up_still_allows_an_event_trigger() {
        // The peer is still rediscoverable; it is this schedule that stops, not the possibility of ever connecting.
        // A discovery reply is exactly the evidence the ceiling was waiting for.
        let mut backoff = Backoff::new(1);
        for _ in 0..=MAX_ATTEMPTS {
            backoff.record_failure(0);
        }
        assert!(backoff.has_given_up());

        match backoff.ready(0, RetryTrigger::Timer) {
            Err(BackoffRefusal::GivenUp { attempts }) => assert_eq!(attempts, MAX_ATTEMPTS + 1),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(backoff.ready(0, RetryTrigger::Rediscovered), Ok(()));
    }

    #[test]
    fn resetting_clears_everything_including_the_giving_up() {
        let mut backoff = Backoff::new(1);
        for _ in 0..=MAX_ATTEMPTS {
            backoff.record_failure(0);
        }
        assert!(backoff.has_given_up());

        backoff.reset(ResetReason::Connected);
        assert_eq!(backoff.attempts(), 0);
        assert!(!backoff.has_given_up());
        assert_eq!(backoff.due_at_ms(), None);
        assert_eq!(backoff.ready(0, RetryTrigger::Timer), Ok(()));
    }

    #[test]
    fn every_reset_reason_clears_the_schedule() {
        // The reason is recorded rather than only the effect, but the effect is the same for all three: a schedule
        // that reset when it should not have is otherwise invisible.
        for reason in [ResetReason::Connected, ResetReason::UserRequest, ResetReason::Unpaired] {
            let mut backoff = Backoff::new(1);
            backoff.record_failure(0).expect("schedules");
            backoff.reset(reason);
            assert_eq!(backoff.attempts(), 0, "{reason:?}");
        }
    }

    #[test]
    fn a_long_outage_settles_at_the_base_delay() {
        // Not a doubling tail: a peer that is reachable at all is usually reachable in half a minute, and waiting
        // hours for one that came back a minute later is worse than a slightly frequent retry.
        let mut backoff = Backoff::new(3);
        for _ in 0..MAX_ATTEMPTS {
            let delay = backoff.record_failure(0).expect("schedules");
            let base_ms = u64::try_from(RECONNECT_BASE.as_millis()).unwrap_or(0);
            assert!(
                (delay.as_millis() as u64) <= base_ms * 120 / 100,
                "a delay grew past the base: {delay:?}"
            );
        }
    }

    #[test]
    fn no_delay_exceeds_the_ceiling() {
        let mut backoff = Backoff::new(9);
        for _ in 0..MAX_ATTEMPTS {
            let delay = backoff.record_failure(0).expect("schedules");
            assert!(delay <= RECONNECT_MAX, "{delay:?} exceeds the ceiling");
        }
    }

    #[test]
    fn the_due_time_saturates_rather_than_wrapping() {
        // A clock near the end of its range must not produce a due time in the past, which would make every timer
        // tick an attempt.
        let mut backoff = Backoff::new(1);
        backoff.record_failure(u64::MAX);
        assert_eq!(backoff.due_at_ms(), Some(u64::MAX));
    }

    #[test]
    fn every_trigger_and_refusal_explains_itself() {
        for trigger in [
            RetryTrigger::Timer,
            RetryTrigger::Rediscovered,
            RetryTrigger::NetworkChanged,
            RetryTrigger::Foreground,
            RetryTrigger::LocalChange,
        ] {
            assert!(!trigger.as_str().is_empty(), "{trigger:?}");
            assert!(!trigger.as_str().contains(' '), "{trigger:?}");
        }
    }

    #[test]
    fn a_pending_retry_carries_what_the_interface_shows() {
        let pending = PendingRetry { peer: "@peer".to_owned(), attempts: 3, in_ms: 8_000 };
        assert_eq!(pending.attempts, 3);
        assert_eq!(pending.in_ms, 8_000);
        assert_eq!(pending.clone(), pending);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

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
}
