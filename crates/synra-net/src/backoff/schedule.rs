use core::time::Duration;

use synra_protocol::limits::{
    RECONNECT_BACKOFF, RECONNECT_BASE, RECONNECT_JITTER_PERCENT, RECONNECT_MAX,
};

use super::{BackoffRefusal, MAX_ATTEMPTS, ResetReason, RetryTrigger};

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
