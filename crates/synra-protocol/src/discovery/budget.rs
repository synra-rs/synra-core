use core::time::Duration;

use crate::limits;

/// How much time and how many connections a scan may spend.
///
/// Defined once, here, and used by every platform. A per-platform timeout is precisely how "the same
/// code behaves differently on each device" starts: a value tuned on a desktop becomes a scan that
/// never finishes on a phone, and nothing in the source says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBudget {
    /// The whole budget, so the interface's "scanning" spinner has a bound.
    pub total: Duration,
    /// How long to listen for replies before probing.
    pub passive: Duration,
    /// How long one TCP probe may take.
    pub probe_timeout: Duration,
    /// How many probes may be in flight at once.
    pub probe_concurrency: usize,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self {
            total: limits::SCAN_TOTAL,
            passive: limits::SCAN_PASSIVE,
            probe_timeout: limits::SCAN_PROBE_TIMEOUT,
            probe_concurrency: limits::SCAN_PROBE_CONCURRENCY,
        }
    }
}

impl ScanBudget {
    /// How long to wait between the repeated broadcast queries.
    #[must_use]
    pub const fn query_interval(&self) -> Duration {
        limits::DISCOVERY_QUERY_INTERVAL
    }

    /// How many times a query is broadcast.
    ///
    /// More than once because a single UDP datagram is lost often enough to matter: a device that
    /// misses the only query appears to be offline. Three attempts covers a one-off loss without
    /// turning discovery into a flood.
    #[must_use]
    pub const fn query_repeats(&self) -> u8 {
        limits::DISCOVERY_QUERY_REPEATS
    }

    /// How long the repeated queries take in total.
    #[must_use]
    pub const fn query_window(&self) -> Duration {
        // `Duration` multiplication by a `u32` is const-stable; the repeat count is a small constant.
        limits::DISCOVERY_QUERY_INTERVAL.saturating_mul(limits::DISCOVERY_QUERY_REPEATS as u32)
    }

    /// Checks the budget is usable.
    ///
    /// # Errors
    ///
    /// A description of the first inconsistency.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.total.is_zero() || self.passive.is_zero() || self.probe_timeout.is_zero() {
            return Err("every scan phase needs a non-zero limit, or a scan never ends");
        }
        if self.probe_concurrency == 0 {
            return Err("probe_concurrency must be non-zero, or no candidate is ever probed");
        }
        if self.passive > self.total {
            return Err("passive must not exceed total, or the probe phase never runs");
        }
        if self.query_window() > self.passive {
            return Err("the repeated queries must fit inside the passive window, \
                 or a query is still going out after replies stopped being collected");
        }
        Ok(())
    }

    /// Whether a set of candidates can be probed inside the budget.
    ///
    /// A scan that cannot finish is worse than one that reports fewer candidates: the interface
    /// shows "scanning" for the full budget and then reports a partial answer with no indication it
    /// was partial.
    #[must_use]
    pub fn can_probe(&self, candidate_count: usize) -> bool {
        let batches = candidate_count.div_ceil(self.probe_concurrency);
        let needed = self.probe_timeout.saturating_mul(batches as u32);
        needed <= self.total.saturating_sub(self.passive)
    }

    /// How long the probe phase has, once listening is done.
    #[must_use]
    pub const fn probe_window(&self) -> Duration {
        self.total.saturating_sub(self.passive)
    }
}
