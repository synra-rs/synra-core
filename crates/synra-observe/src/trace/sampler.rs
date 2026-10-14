use std::collections::HashSet;

use parking_lot::RwLock;

use synra_protocol::TraceId;

use super::identity::TraceContext;

/// The sampling policy.
///
/// See the module docs for why the decision is made once. This type only decides *whether* to record; it
/// does not decide what to record.
#[derive(Debug)]
pub struct Sampler {
    /// Whether a trace that is already known to have failed is always recorded.
    always_on_error: bool,
    /// A duration, in milliseconds, above which a trace is always recorded.
    always_slower_than_ms: u64,
    /// The rate for everything else, in parts per million.
    ///
    /// An integer rather than a float so the decision is reproducible: two runs of the same trace produce
    /// the same sampling decision, and a test does not need a tolerance.
    base_rate_ppm: u32,
    /// Traces the user asked to record in full.
    forced: RwLock<HashSet<TraceId>>,
    /// A counter, so the probability is exercised rather than approximated by a random draw per call.
    counter: RwLock<u64>,
}

/// The default rate: one per cent, in parts per million.
pub const DEFAULT_BASE_RATE_PPM: u32 = 10_000;

/// The default "always record" threshold, in milliseconds.
pub const DEFAULT_ALWAYS_SLOWER_THAN_MS: u64 = 200;

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

impl Sampler {
    /// A sampler with the documented defaults: errors always, over 200 ms always, one per cent otherwise.
    #[must_use]
    pub fn new() -> Self {
        Self {
            always_on_error: true,
            always_slower_than_ms: DEFAULT_ALWAYS_SLOWER_THAN_MS,
            base_rate_ppm: DEFAULT_BASE_RATE_PPM,
            forced: RwLock::new(HashSet::new()),
            counter: RwLock::new(0),
        }
    }

    /// A sampler with the given rate, for a test or a verbose mode.
    #[must_use]
    pub fn with_rate_ppm(base_rate_ppm: u32) -> Self {
        Self { base_rate_ppm, ..Self::new() }
    }

    /// A sampler that records everything.
    #[must_use]
    pub fn everything() -> Self {
        Self::with_rate_ppm(1_000_000)
    }

    /// A sampler that records nothing but the forced traces.
    #[must_use]
    pub fn nothing() -> Self {
        Self::with_rate_ppm(0)
    }

    /// Whether a trace that has not finished yet should be recorded.
    ///
    /// `outcome_unknown` is `true` for a step whose outcome is not yet known — the usual case at the start,
    /// because a trace begins before anything has failed. An error discovered later raises the decision to
    /// "record" for that trace, which is why [`Self::should_sample`] is only the first half of the policy:
    /// see [`Self::force`].
    #[must_use]
    pub fn should_sample(&self, outcome_unknown: bool) -> bool {
        if !outcome_unknown && self.always_on_error {
            return true;
        }
        self.roll()
    }

    /// Whether a trace is recorded given its duration and whether it failed.
    ///
    /// The decision a finished trace can make, and the one a caller uses when it has the outcome in hand.
    #[must_use]
    pub fn should_sample_finished(&self, failed: bool, elapsed_ms: u64) -> bool {
        if failed && self.always_on_error {
            return true;
        }
        if elapsed_ms > self.always_slower_than_ms {
            return true;
        }
        self.roll()
    }

    /// Records a trace in full from now on.
    ///
    /// The diagnostics screen offers "record the next operation in detail", which is the single most
    /// useful thing a user can do for a maintainer. It works by forcing the next trace rather than by
    /// raising the global rate, so one investigation does not flood the log.
    pub fn force(&self, trace_id: TraceId) {
        self.forced.write().insert(trace_id);
    }

    /// Whether a trace was forced.
    #[must_use]
    pub fn is_forced(&self, trace_id: TraceId) -> bool {
        self.forced.read().contains(&trace_id)
    }

    /// Stops recording a trace in full.
    pub fn unforce(&self, trace_id: TraceId) {
        self.forced.write().remove(&trace_id);
    }

    /// How many traces are forced.
    #[must_use]
    pub fn forced_count(&self) -> usize {
        self.forced.read().len()
    }

    /// Forgets every forced trace.
    pub fn clear_forced(&self) {
        self.forced.write().clear();
    }

    /// Decides the base rate by counter.
    ///
    /// Deterministic rather than random: a counter modulo a million hits exactly the configured proportion
    /// over any long run, where a random draw would cluster and make a sampled trace's coverage impossible
    /// to reason about. The practical benefit is that a test can assert the rate rather than a range.
    fn roll(&self) -> bool {
        if self.base_rate_ppm == 0 {
            return false;
        }
        if self.base_rate_ppm >= 1_000_000 {
            return true;
        }
        // The position is read and the counter advanced in a single block, so the guard is not a temporary
        // inside an expression whose result outlives it.
        let position = {
            let mut counter = self.counter.write();
            let position = *counter;
            *counter = counter.wrapping_add(1);
            position
        };
        position % 1_000_000 < u64::from(self.base_rate_ppm)
    }

    /// Whether a trace will be recorded, taking a forced trace into account.
    ///
    /// The method a caller should use. It exists so the forced set is consulted in one place: a caller that
    /// checked the rate itself would ignore the user's "record this one" request.
    #[must_use]
    pub fn should_record(&self, context: &TraceContext, failed: bool, elapsed_ms: u64) -> bool {
        if self.is_forced(context.trace_id) {
            return true;
        }
        if context.sampled {
            return true;
        }
        self.should_sample_finished(failed, elapsed_ms)
    }
}
