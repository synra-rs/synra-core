//! The token bucket, and the refusals that persist.

use core::time::Duration;

use serde::{Deserialize, Serialize};

use super::limits::RateKind;
/// A token bucket.
///
/// Refills continuously rather than in ticks. A tick-based bucket gives a plugin nothing for the rest of the
/// second after it exhausts one, which turns a burst into a stall and makes the observed rate depend on where in
/// the second the burst started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBucket {
    /// Tokens available, scaled so a fractional refill is representable.
    ///
    /// Scaled by [`Self::SCALE`] so a bucket that refills at half a token per millisecond can be represented
    /// without floating point — a limit that behaves differently on two platforms is worse than one that rounds.
    tokens: u64,
    /// The most tokens it may hold, scaled.
    capacity: u64,
    /// Tokens added per second, scaled.
    refill_per_sec: u64,
    /// When it was last refilled, as a monotonic millisecond count.
    last_refill_ms: u64,
}

impl TokenBucket {
    /// The fixed-point scale.
    ///
    /// A thousand: enough that one token per second refills at one unit per millisecond, which is the finest
    /// granularity any of these limits needs.
    pub const SCALE: u64 = 1_000;

    /// A full bucket.
    #[must_use]
    pub fn new(rate_per_sec: u32, burst: u32, now_ms: u64) -> Self {
        let capacity = u64::from(burst).saturating_mul(Self::SCALE);
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: u64::from(rate_per_sec).saturating_mul(Self::SCALE),
            last_refill_ms: now_ms,
        }
    }

    /// How many whole tokens are available.
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.tokens / Self::SCALE
    }

    /// The most it may hold.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity / Self::SCALE
    }

    /// Adds the tokens earned since the last refill.
    ///
    /// A time earlier than the last refill adds nothing rather than subtracting: the caller's clock is monotonic,
    /// and a bucket that lost tokens on a backwards reading would refuse a call it had already earned.
    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_refill_ms {
            return;
        }
        let elapsed_ms = now_ms - self.last_refill_ms;
        let earned = self.refill_per_sec.saturating_mul(elapsed_ms) / 1_000;
        self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
        self.last_refill_ms = now_ms;
    }

    /// Takes `count` tokens if they are available.
    ///
    /// # Errors
    ///
    /// [`RateLimited`] with how long to wait.
    pub fn try_consume(&mut self, count: u32, now_ms: u64) -> Result<(), RateLimited> {
        self.refill(now_ms);

        let wanted = u64::from(count).saturating_mul(Self::SCALE);
        if self.tokens >= wanted {
            self.tokens -= wanted;
            return Ok(());
        }

        let shortfall = wanted - self.tokens;
        // A bucket with no refill rate would wait forever, so the answer is the maximum rather than a division by
        // zero. A caller showing this says "not for a very long time" rather than hanging on an arithmetic error.
        let wait_ms = if self.refill_per_sec == 0 {
            u64::MAX
        }
        else {
            shortfall.saturating_mul(1_000).div_ceil(self.refill_per_sec)
        };
        Err(RateLimited { kind: None, retry_after_ms: wait_ms, shortfall })
    }

    /// Resets to full, for a plugin that has been re-enabled.
    pub const fn refill_fully(&mut self, now_ms: u64) {
        self.tokens = self.capacity;
        self.last_refill_ms = now_ms;
    }
}

/// Why a call was refused for rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("rate limited; try again in {retry_after_ms}ms")]
pub struct RateLimited {
    /// Which kind, when the refusal came from a limiter that knows.
    pub kind: Option<RateKind>,
    /// How long to wait.
    pub retry_after_ms: u64,
    /// How many tokens were missing.
    pub shortfall: u64,
}

impl RateLimited {
    /// How long to wait.
    #[must_use]
    pub const fn retry_after(&self) -> Duration {
        Duration::from_millis(self.retry_after_ms)
    }
}

/// A static limit that was exceeded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StaticRefusal {
    /// The plugin would hold more memory than allowed.
    #[error("the plugin would use {wanted} bytes of memory, and its limit is {limit}")]
    Memory {
        /// What it asked for.
        wanted: u64,
        /// The limit.
        limit: u64,
    },
    /// The plugin asked for more instances than allowed.
    #[error("the plugin would have {wanted} instances, and its limit is {limit}")]
    Instances {
        /// What it asked for.
        wanted: u32,
        /// The limit.
        limit: u32,
    },
    /// The plugin would store more than allowed.
    #[error("the plugin would store {wanted} bytes, and its limit is {limit}")]
    Storage {
        /// What it asked for.
        wanted: u64,
        /// The limit.
        limit: u64,
    },
    /// The plugin asked for more transfers than allowed.
    #[error("the plugin would have {wanted} open transfers, and its limit is {limit}")]
    Transfers {
        /// What it asked for.
        wanted: u32,
        /// The limit.
        limit: u32,
    },
}

impl StaticRefusal {
    /// Whether a caller may try again later.
    ///
    /// Never. A static limit is a decision about how much a plugin may hold, so retrying against it is retrying
    /// against the host's own configuration. A rate, by contrast, is a refusal that says when.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}
