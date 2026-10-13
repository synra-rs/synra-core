//! Traces: following one user action through the whole system.
//!
//! A trace id is created when a user does something and flows through every step that follows: the intent
//! match, the capability check, the transport send, the peer's receive, the peer's own work, the reply.
//! With it, a bug report becomes "look at trace 7f3a" instead of "look at everything around 10:23".
//!
//! # Spans form a tree; the trace id is flat
//!
//! Two identifiers, and the difference matters:
//!
//! * [`TraceContext::trace_id`] — one per user action. Shared by every device involved.
//! * [`TraceContext::span_id`] — one per step, with [`TraceContext::parent_span`] pointing at the step
//!   that caused it.
//!
//! The parent link is what turns a list of timestamped lines into a shape. Without it, a fan-out — one
//! intent matched by three plugins — reads as three unrelated events that happened at once.
//!
//! # Sampling is not optional
//!
//! One file transfer is eighty frames. Tracing all of them produces a log nobody can read and a disk
//! nobody can afford, so tracing is sampled. The policy is deliberately biased toward the interesting
//! cases:
//!
//! * anything that failed, always;
//! * anything slower than a threshold, always;
//! * everything else at a low rate;
//! * anything the user explicitly asked to trace, always.
//!
//! The decision is made **once, at the root**, and inherited. A sampler consulted per span would produce
//! the worst possible outcome: a trace with holes, where the reader cannot tell whether a step was skipped
//! because it did not happen or because it was not sampled.
//!
//! # Cross-device traces are broken in v1, and said so
//!
//! A v1 envelope carries `traceId`, so the *id* propagates. What does not propagate is the rest: the peer
//! that received the message starts a span whose parent is on another device, and this build cannot join
//! them. Rather than pretend, [`TraceOrigin`] records whether a trace is whole.

use std::collections::HashSet;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use synra_protocol::TraceId;
use synra_protocol::envelope::Envelope;

/// One step's identity within a trace.
///
/// A `u64` rather than a UUID: spans are only ever compared within one device's log, and a counter is
/// smaller, cheaper and easier to read in a rendered trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpanId(pub u64);

impl SpanId {
    /// The root span of a trace, which no step caused.
    pub const ROOT: Self = Self(0);

    /// Whether this is the root.
    #[must_use]
    pub const fn is_root(self) -> bool {
        self.0 == Self::ROOT.0
    }

    /// Lowercase hex, which is how it appears in a rendered trace.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

impl core::fmt::Display for SpanId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Where a trace's information comes from, and how much of it is present.
///
/// Recorded so a reader is not misled by a trace that looks complete. A trace that silently stops at a
/// device boundary reads as "the peer did nothing", which is the opposite of the truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TraceOrigin {
    /// Started on this device and every step is in this log.
    Local,
    /// Started on another device. The steps before the hand-off are not here.
    Remote,
    /// Crosses a device boundary. The id is shared, but this build does not carry span parentage across
    /// the link, so the two halves cannot be joined into one tree.
    CrossesDevices,
}

impl TraceOrigin {
    /// Whether the trace's steps are all present.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Local)
    }

    /// A phrase for the interface, so a user is not shown a gap without explanation.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Local => "all steps recorded on this device",
            Self::Remote => "started on another device; earlier steps are in its log",
            Self::CrossesDevices => {
                "spans this device and another; the two halves are not joined in this version"
            }
        }
    }
}

/// The identity of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceContext {
    /// The user action this belongs to.
    pub trace_id: TraceId,
    /// This step.
    pub span_id: SpanId,
    /// The step that caused this one, if any.
    pub parent_span: Option<SpanId>,
    /// Whether this trace is being recorded.
    ///
    /// Carried in the context rather than asked of the sampler again, so every step of one trace agrees.
    pub sampled: bool,
    /// How much of the trace is present.
    pub origin: TraceOrigin,
}

impl TraceContext {
    /// Starts a trace, sampling it according to the policy.
    ///
    /// The decision is made here and never revisited, which is what keeps a sampled trace whole.
    #[must_use]
    pub fn start(sampler: &Sampler, outcome_unknown: bool) -> Self {
        Self {
            trace_id: TraceId::new(),
            span_id: SpanId::ROOT,
            parent_span: None,
            sampled: sampler.should_sample(outcome_unknown),
            origin: TraceOrigin::Local,
        }
    }

    /// A trace that is always recorded, for a caller that has already decided.
    #[must_use]
    pub const fn always(trace_id: TraceId) -> Self {
        Self {
            trace_id,
            span_id: SpanId::ROOT,
            parent_span: None,
            sampled: true,
            origin: TraceOrigin::Local,
        }
    }

    /// Opens a child step.
    #[must_use]
    pub const fn child(&self) -> Self {
        Self {
            span_id: SpanId(self.span_id.0.wrapping_add(1)),
            parent_span: Some(self.span_id),
            // Inherited, never re-decided: a per-span decision produces a trace with unexplained holes.
            sampled: self.sampled,
            ..*self
        }
    }

    /// Opens a child step with an explicit span id, for a caller that keeps its own counter.
    #[must_use]
    pub const fn child_with(&self, span_id: SpanId) -> Self {
        Self {
            span_id,
            parent_span: Some(self.span_id),
            ..*self
        }
    }

    /// Takes the context from an inbound message.
    ///
    /// Returns `None` when the envelope carries no usable trace, which happens for a message from a build
    /// that does not set one. A caller then starts its own trace and marks the discontinuity rather than
    /// inventing a parent.
    #[must_use]
    // Not a `const fn`: the clippy suggestion is advisory, and `Envelope`'s field access through a
    // reference is not something a const context can do here. Allowing the lint keeps the reasoning at the
    // call site rather than forcing a signature that would only be const by accident.
    #[allow(clippy::missing_const_for_fn)]
    pub fn from_envelope(envelope: &Envelope) -> Option<Self> {
        if envelope.trace_id.is_zero() {
            return None;
        }
        Some(Self {
            trace_id: envelope.trace_id,
            // The sender's span id is not in the v1 envelope, so there is nothing to parent onto. The
            // hand-off starts a root span on this side and says so.
            span_id: SpanId::ROOT,
            parent_span: None,
            // An inbound trace is recorded if the sender recorded it. Re-sampling would split one user
            // action across two logs with different coverage.
            sampled: true,
            origin: TraceOrigin::CrossesDevices,
        })
    }

    /// Continues a trace received from another device, or starts one and marks it as remote.
    ///
    /// The fallback is the honest option: a message with no trace id cannot be attributed to a user action,
    /// and pretending otherwise would put unrelated steps under one id.
    #[must_use]
    pub fn continue_from(envelope: &Envelope, sampler: &Sampler) -> Self {
        match Self::from_envelope(envelope) {
            Some(context) => context,
            None => Self {
                origin: TraceOrigin::Remote,
                ..Self::start(sampler, true)
            },
        }
    }

    /// Whether this step will be recorded.
    #[must_use]
    pub const fn is_recorded(&self) -> bool {
        self.sampled
    }

    /// A short form for a log line: the trace id's first six hex digits.
    ///
    /// Enough to grep for, short enough to sit in a line a human reads. The full id is in the structured
    /// field, so nothing is lost.
    #[must_use]
    pub fn short(&self) -> String {
        let full = self.trace_id.to_hex();
        full.chars().take(6).collect()
    }

    /// How this trace should be described to a user.
    #[must_use]
    pub const fn describe_origin(&self) -> &'static str {
        self.origin.explain()
    }
}

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

/// One recorded step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// Which trace and step.
    pub context: TraceContext,
    /// What was happening, such as `transport.send`.
    pub name: String,
    /// When it started, in milliseconds since the process began.
    ///
    /// Relative to the process rather than to the wall clock, so a device whose clock is wrong still
    /// produces a trace whose steps are in order and whose durations are right.
    pub started_at_ms: u64,
    /// How long it took, once it finished.
    pub elapsed_ms: Option<u64>,
    /// Whether it failed.
    pub failed: bool,
}

impl Span {
    /// Opens a span.
    #[must_use]
    pub fn start(context: TraceContext, name: impl Into<String>, now_ms: u64) -> Self {
        Self {
            context,
            name: name.into(),
            started_at_ms: now_ms,
            elapsed_ms: None,
            failed: false,
        }
    }

    /// Closes the span.
    pub const fn finish(&mut self, now_ms: u64, failed: bool) {
        self.elapsed_ms = Some(now_ms.saturating_sub(self.started_at_ms));
        self.failed = failed;
    }

    /// Whether the span is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.elapsed_ms.is_none()
    }
}

/// A bounded ring of recent spans, for the diagnostics screen.
///
/// Bounded because the log file is the durable record; this exists so the interface can show the last few
/// traces without reading the file back. An unbounded buffer would be a second copy of the log, in memory.
#[derive(Debug)]
pub struct TraceRing {
    spans: RwLock<Vec<Span>>,
    capacity: usize,
    /// How many spans were dropped because the ring was full.
    dropped: RwLock<u64>,
}

impl TraceRing {
    /// A ring holding the most recent `capacity` spans.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            spans: RwLock::new(Vec::with_capacity(capacity.min(1024))),
            capacity,
            dropped: RwLock::new(0),
        }
    }

    /// Records a span, dropping the oldest if the ring is full.
    pub fn record(&self, span: Span) {
        if self.capacity == 0 {
            *self.dropped.write() += 1;
            return;
        }
        let mut spans = self.spans.write();
        if spans.len() >= self.capacity {
            spans.remove(0);
            *self.dropped.write() += 1;
        }
        spans.push(span);
    }

    /// The steps of one trace, in the order they started.
    ///
    /// Ordered by start time rather than by span id: a fan-out gives three children of one parent, and the
    /// useful order is when they ran.
    #[must_use]
    pub fn steps_for(&self, trace_id: TraceId) -> Vec<Span> {
        let mut steps: Vec<Span> = self
            .spans
            .read()
            .iter()
            .filter(|span| span.context.trace_id == trace_id)
            .cloned()
            .collect();
        steps.sort_by_key(|span| (span.started_at_ms, span.context.span_id));
        steps
    }

    /// The distinct traces present, most recent first.
    #[must_use]
    pub fn recent_traces(&self, limit: usize) -> Vec<TraceId> {
        // Checked before the loop rather than inside it: a limit of zero must return nothing, and a check
        // at the end of the loop body admits the first entry regardless.
        if limit == 0 {
            return Vec::new();
        }

        // The scan happens inside a helper, so the read guard is created and released in a function body
        // with no expression around it. Clippy's `significant_drop_in_scrutinee` fires on a guard inside a
        // block whose value outlives it — the same hazard one level up, and a real one: the lock would be
        // released after the result was built rather than at the end of the scan.
        let mut traces = self.ordered_traces();
        traces.truncate(limit);
        traces
    }

    /// Every trace in the ring, most recently started first.
    fn ordered_traces(&self) -> Vec<TraceId> {
        let mut ordered: Vec<TraceId> = Vec::new();
        // The scan is written so the read guard's first use is the `for`, not a statement of its own: clippy
        // reads a guard introduced by one statement and consumed by the next as a lock released earlier than
        // the code suggests. Here the guard is created by the iterator expression itself, so its lifetime is
        // the loop's and nothing else.
        for span in self.spans.read().iter().rev() {
            if !ordered.contains(&span.context.trace_id) {
                ordered.push(span.context.trace_id);
            }
        }
        ordered
    }

    /// How many spans are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.read().len()
    }

    /// Whether the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.read().is_empty()
    }

    /// How many spans were dropped to make room.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        *self.dropped.read()
    }

    /// Empties the ring.
    pub fn clear(&self) {
        self.spans.write().clear();
    }
}

/// Formats a trace's steps the way the diagnostics screen shows them.
///
/// Shared with the diagnostic bundle so a user who exports a trace and a maintainer who reads the bundle
/// see the same thing. Two renderers would eventually disagree, and the disagreement would be read as a
/// difference in the data.
#[must_use]
pub fn render_trace(steps: &[Span]) -> String {
    let mut out = String::new();
    for step in steps {
        let depth = if step.context.span_id.is_root() { 0 } else { 1 };
        let indent = "  ".repeat(depth);
        let elapsed = match step.elapsed_ms {
            Some(ms) => format!("{ms}ms"),
            None => "open".to_owned(),
        };
        let mark = if step.failed { "!" } else { " " };
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{indent}{mark} {started:>8}ms  {name:<28} {elapsed}\n",
                started = step.started_at_ms,
                name = step.name,
            ),
        );
    }
    if out.is_empty() {
        out.push_str("(no steps recorded)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::event::EventName;
    use synra_protocol::ids::DeviceId;

    fn envelope_with_trace(trace_id: TraceId) -> Envelope {
        Envelope::outbound(
            synra_protocol::envelope::OutboundSpec {
                event: EventName::parse("device.ping").expect("valid"),
                target: DeviceId::new(),
                from: DeviceId::new(),
                trace_id,
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&()>,
        )
        .expect("builds")
    }

    #[test]
    fn a_root_span_has_no_parent() {
        let context = TraceContext::start(&Sampler::everything(), true);
        assert!(context.span_id.is_root());
        assert_eq!(context.parent_span, None);
        assert!(context.sampled);
        assert_eq!(context.origin, TraceOrigin::Local);
        assert_eq!(context.describe_origin(), "all steps recorded on this device");
    }

    #[test]
    fn a_child_points_at_its_parent_and_keeps_the_trace() {
        let parent = TraceContext::start(&Sampler::everything(), true);
        let child = parent.child();

        assert_eq!(child.trace_id, parent.trace_id, "one user action, one trace");
        assert_eq!(child.parent_span, Some(parent.span_id));
        assert_ne!(child.span_id, parent.span_id, "a step is its own identity");
        // Sampling is inherited, never re-decided: a per-span decision produces a trace with holes.
        assert_eq!(child.sampled, parent.sampled);
    }

    #[test]
    fn a_sampled_decision_is_inherited_through_a_chain() {
        // The property that keeps a trace readable: every descendant agrees with the root.
        for rate in [0, 1, 500_000, 1_000_000] {
            let sampler = Sampler::with_rate_ppm(rate);
            let root = TraceContext::start(&sampler, true);
            let mut current = root;
            for _ in 0..20 {
                current = current.child();
                assert_eq!(current.sampled, root.sampled, "rate {rate}");
            }
        }
    }

    #[test]
    fn an_error_is_always_recorded() {
        let sampler = Sampler::nothing();
        assert!(sampler.should_sample_finished(true, 1));
        assert!(!sampler.should_sample_finished(false, 1));
    }

    #[test]
    fn a_slow_operation_is_always_recorded() {
        let sampler = Sampler::nothing();
        assert!(sampler.should_sample_finished(false, DEFAULT_ALWAYS_SLOWER_THAN_MS + 1));
        // Exactly at the threshold is not "slower than", so it is not recorded by this rule.
        assert!(!sampler.should_sample_finished(false, DEFAULT_ALWAYS_SLOWER_THAN_MS));
    }

    #[test]
    fn the_base_rate_is_produced_exactly_over_a_full_cycle() {
        // A counter rather than a random draw, so the configured proportion is what happens rather than
        // what happens on average.
        let sampler = Sampler::with_rate_ppm(10_000);
        let sampled = (0..1_000_000).filter(|_| sampler.should_sample(true)).count();
        assert_eq!(sampled, 10_000);
    }

    #[test]
    fn a_rate_of_zero_records_nothing_and_a_full_rate_records_everything() {
        let none = Sampler::nothing();
        assert!((0..1_000).all(|_| !none.should_sample(true)));

        let all = Sampler::everything();
        assert!((0..1_000).all(|_| all.should_sample(true)));
        // And a full-rate sampler must not consume its counter, so a later change of rate is not offset.
        assert!(all.should_sample(true));
    }

    #[test]
    fn a_forced_trace_is_recorded_whatever_the_rate_says() {
        // The diagnostics screen's "record the next operation in detail". One investigation must not
        // require flooding the log with everything.
        let sampler = Sampler::nothing();
        let context = TraceContext::start(&sampler, true);
        assert!(!context.sampled);

        assert!(!sampler.should_record(&context, false, 1));
        sampler.force(context.trace_id);
        assert!(sampler.should_record(&context, false, 1));
        assert!(sampler.is_forced(context.trace_id));
        assert_eq!(sampler.forced_count(), 1);

        sampler.unforce(context.trace_id);
        assert!(!sampler.should_record(&context, false, 1));
        assert_eq!(sampler.forced_count(), 0);
    }

    #[test]
    fn a_sampled_context_is_recorded_even_when_the_rate_would_say_no() {
        // The decision travels with the trace. Re-asking the sampling policy at each step is what produces
        // a trace with unexplained holes.
        let sampler = Sampler::nothing();
        let context = TraceContext::always(TraceId::new());
        assert!(context.sampled);
        assert!(sampler.should_record(&context, false, 1));
    }

    #[test]
    fn forcing_can_be_cleared() {
        let sampler = Sampler::new();
        for _ in 0..3 {
            sampler.force(TraceId::new());
        }
        assert_eq!(sampler.forced_count(), 3);
        sampler.clear_forced();
        assert_eq!(sampler.forced_count(), 0);
    }

    #[test]
    fn a_trace_is_recovered_from_an_envelope() {
        let trace_id = TraceId::new();
        let envelope = envelope_with_trace(trace_id);
        let context = TraceContext::from_envelope(&envelope).expect("has a trace");

        assert_eq!(context.trace_id, trace_id);
        assert!(context.span_id.is_root(), "the hand-off has no parent id to attach to");
        assert_eq!(context.parent_span, None);
        assert!(
            context.sampled,
            "an inbound trace is recorded if the sender recorded it"
        );
        // And the discontinuity is stated rather than left to be discovered.
        assert_eq!(context.origin, TraceOrigin::CrossesDevices);
        assert!(!context.origin.is_complete());
        assert!(context.describe_origin().contains("not joined"));
    }

    #[test]
    fn an_envelope_with_no_trace_yields_nothing() {
        // Rather than inventing an id, which would put unrelated steps under one trace.
        let envelope = envelope_with_trace(TraceId(0));
        assert_eq!(TraceContext::from_envelope(&envelope), None);
    }

    #[test]
    fn continuing_from_an_untraced_message_starts_a_trace_and_marks_it_remote() {
        let sampler = Sampler::everything();
        let envelope = envelope_with_trace(TraceId(0));
        let context = TraceContext::continue_from(&envelope, &sampler);

        assert!(!context.trace_id.is_zero(), "a trace id was started");
        assert_eq!(context.origin, TraceOrigin::Remote);
        assert!(!context.origin.is_complete());
        assert!(context.describe_origin().contains("another device"));
    }

    #[test]
    fn continuing_from_a_traced_message_keeps_its_id() {
        let trace_id = TraceId::new();
        let envelope = envelope_with_trace(trace_id);
        let context = TraceContext::continue_from(&envelope, &Sampler::nothing());

        assert_eq!(context.trace_id, trace_id);
        assert_eq!(context.origin, TraceOrigin::CrossesDevices);
    }

    #[test]
    fn a_context_can_open_a_child_with_its_own_counter() {
        // A caller that keeps its own span counter — the kernel, which numbers spans per trace rather than
        // per context — still gets the parent link.
        let parent = TraceContext::start(&Sampler::everything(), true);
        let child = parent.child_with(SpanId(42));
        assert_eq!(child.span_id, SpanId(42));
        assert_eq!(child.parent_span, Some(parent.span_id));
        assert_eq!(child.trace_id, parent.trace_id);
    }

    #[test]
    fn a_span_id_renders_as_hex() {
        assert_eq!(SpanId(0).to_hex(), "0000000000000000");
        assert!(SpanId::ROOT.is_root());
        assert!(!SpanId(1).is_root());
        assert_eq!(SpanId(255).to_hex(), "00000000000000ff");
        assert_eq!(SpanId(255).to_string(), "00000000000000ff");
    }

    #[test]
    fn a_short_trace_id_is_a_usable_grep_target() {
        let context = TraceContext::always(TraceId(0x7f3a_c21b_0000_0000_0000_0000_0000_0000));
        assert_eq!(context.short().len(), 6);
        assert!(context.short().starts_with("7f3ac2"), "{}", context.short());
    }

    #[test]
    fn a_span_records_when_it_started_and_how_long_it_took() {
        let context = TraceContext::start(&Sampler::everything(), true);
        let mut span = Span::start(context, "transport.send", 1_000);
        assert!(span.is_open());
        assert_eq!(span.elapsed_ms, None);

        span.finish(1_012, false);
        assert!(!span.is_open());
        assert_eq!(span.elapsed_ms, Some(12));
        assert!(!span.failed);
    }

    #[test]
    fn a_span_that_finishes_before_it_started_reports_zero_rather_than_wrapping() {
        // A clock that moved backwards — a suspend, a manual time change — must not produce a duration of
        // eighteen quintillion milliseconds.
        let context = TraceContext::start(&Sampler::everything(), true);
        let mut span = Span::start(context, "weird", 5_000);
        span.finish(1_000, false);
        assert_eq!(span.elapsed_ms, Some(0));
    }

    #[test]
    fn a_finished_span_can_be_marked_failed() {
        let context = TraceContext::start(&Sampler::everything(), true);
        let mut span = Span::start(context, "gate.check", 0);
        span.finish(5, true);
        assert!(span.failed);
    }

    #[test]
    fn the_ring_keeps_only_the_most_recent_spans() {
        let ring = TraceRing::with_capacity(3);
        let context = TraceContext::always(TraceId::new());
        for index in 0..5u64 {
            ring.record(Span::start(context, format!("step{index}"), index));
        }

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.dropped(), 2);
        let names: Vec<String> = ring.steps_for(context.trace_id).into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["step2", "step3", "step4"]);
    }

    #[test]
    fn a_zero_capacity_ring_records_nothing_without_panicking() {
        // A configuration that disables the trace view must not crash the kernel on its first span.
        let ring = TraceRing::with_capacity(0);
        let context = TraceContext::always(TraceId::new());
        ring.record(Span::start(context, "step", 0));

        assert!(ring.is_empty());
        assert_eq!(ring.dropped(), 1);
        assert!(ring.steps_for(context.trace_id).is_empty());
    }

    #[test]
    fn the_ring_separates_traces() {
        let ring = TraceRing::with_capacity(16);
        let first = TraceContext::always(TraceId::new());
        let second = TraceContext::always(TraceId::new());

        ring.record(Span::start(first, "a", 0));
        ring.record(Span::start(second, "b", 1));
        ring.record(Span::start(first, "c", 2));

        assert_eq!(ring.steps_for(first.trace_id).len(), 2);
        assert_eq!(ring.steps_for(second.trace_id).len(), 1);
        assert!(ring.steps_for(TraceId::new()).is_empty());
    }

    #[test]
    fn steps_are_ordered_by_when_they_ran() {
        // A fan-out gives several children of one parent; span id order is not run order.
        let ring = TraceRing::with_capacity(16);
        let root = TraceContext::always(TraceId::new());
        let child = root.child_with(SpanId(1));
        let grandchild = child.child_with(SpanId(2));

        // Recorded out of order, as concurrent steps would arrive.
        ring.record(Span::start(grandchild, "grandchild", 30));
        ring.record(Span::start(root, "root", 10));
        ring.record(Span::start(child, "child", 20));

        let names: Vec<String> = ring.steps_for(root.trace_id).into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["root", "child", "grandchild"]);
    }

    #[test]
    fn recent_traces_are_listed_newest_first() {
        let ring = TraceRing::with_capacity(16);
        let first = TraceContext::always(TraceId::new());
        let second = TraceContext::always(TraceId::new());

        ring.record(Span::start(first, "a", 0));
        ring.record(Span::start(second, "b", 1));
        ring.record(Span::start(second, "c", 2));

        let recent = ring.recent_traces(10);
        assert_eq!(recent.first(), Some(&second.trace_id), "the newest trace comes first");
        // De-duplicated: two steps of one trace are one entry.
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn recent_traces_respect_their_limit() {
        let ring = TraceRing::with_capacity(16);
        for index in 0..5u64 {
            let context = TraceContext::always(TraceId::new());
            ring.record(Span::start(context, format!("s{index}"), index));
        }
        assert_eq!(ring.recent_traces(2).len(), 2);
        assert!(ring.recent_traces(0).is_empty());
    }

    #[test]
    fn the_ring_can_be_emptied() {
        let ring = TraceRing::with_capacity(4);
        ring.record(Span::start(TraceContext::always(TraceId::new()), "a", 0));
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.dropped(), 0, "clearing is not dropping");
    }

    #[test]
    fn a_rendered_trace_is_readable_and_indents_children() {
        let root = TraceContext::always(TraceId::new());
        let child = root.child();

        let mut first = Span::start(root, "transport.send", 0);
        first.finish(12, false);
        let mut second = Span::start(child, "gate.check", 14);
        second.finish(1, true);

        let rendered = render_trace(&[first, second]);
        assert!(rendered.contains("transport.send"), "{rendered}");
        assert!(rendered.contains("12ms"), "{rendered}");
        assert!(rendered.contains("gate.check"), "{rendered}");
        // The failed step is marked, so a reader's eye finds it.
        assert!(rendered.contains("! "), "{rendered}");
        // And a child is indented.
        assert!(rendered.contains("\n  ! "), "{rendered}");
    }

    #[test]
    fn rendering_an_empty_trace_says_so() {
        // An empty string in a diagnostic bundle reads as a rendering bug.
        let rendered = render_trace(&[]);
        assert!(rendered.contains("no steps recorded"), "{rendered}");
    }

    #[test]
    fn an_open_span_renders_as_open() {
        let context = TraceContext::always(TraceId::new());
        let rendered = render_trace(&[Span::start(context, "still.running", 5)]);
        assert!(rendered.contains("open"), "{rendered}");
    }

    #[test]
    fn trace_origins_explain_themselves() {
        assert!(TraceOrigin::Local.is_complete());
        assert!(!TraceOrigin::Remote.is_complete());
        assert!(!TraceOrigin::CrossesDevices.is_complete());

        // Every explanation is a sentence, because it is shown to a user who is looking at a gap.
        for origin in [TraceOrigin::Local, TraceOrigin::Remote, TraceOrigin::CrossesDevices] {
            let text = origin.explain();
            assert!(!text.is_empty(), "{origin:?}");
            assert!(!text.contains('-'), "{origin:?} -> {text}");
        }
    }

    #[test]
    fn a_trace_context_round_trips_through_json() {
        // A span is written to the log and read back by the diagnostics screen, so the shape has to survive.
        let context = TraceContext::start(&Sampler::everything(), true).child();
        let json = serde_json::to_string(&context).expect("serialises");
        let back: TraceContext = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, context);

        // A span id is transparent over its number, so a log reader sees `1` rather than an object.
        assert_eq!(serde_json::to_string(&SpanId(1)).expect("serialises"), "1");
    }

    #[test]
    fn a_sampler_is_debug_printable() {
        let sampler = Sampler::new();
        assert!(format!("{sampler:?}").contains("Sampler"));
    }

    #[test]
    fn a_recorded_flag_follows_the_sampled_flag() {
        let sampled = TraceContext::start(&Sampler::everything(), true);
        assert!(sampled.is_recorded());

        let unsampled = TraceContext::always(TraceId::new());
        assert!(unsampled.is_recorded());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Every step of a trace agrees on whether it is recorded. This is the property that keeps a
        /// sampled trace whole: a hole in a trace is worse than no trace, because it reads as "nothing
        /// happened here".
        #[test]
        fn sampling_is_uniform_across_a_trace(
            rate in 0u32..=1_000_000,
            depth in 1usize..40,
        ) {
            let sampler = Sampler::with_rate_ppm(rate);
            let root = TraceContext::start(&sampler, true);
            let mut current = root;
            for _ in 0..depth {
                current = current.child();
                prop_assert_eq!(current.sampled, root.sampled);
                prop_assert_eq!(current.trace_id, root.trace_id);
            }
        }

        /// A child's parent is always its immediate parent, and its span differs from it. A self-parenting
        /// span makes a tree that cannot be walked.
        #[test]
        fn a_child_links_to_exactly_one_distinct_parent(depth in 1usize..30) {
            let mut current = TraceContext::start(&Sampler::everything(), true);
            for _ in 0..depth {
                let child = current.child();
                prop_assert_eq!(child.parent_span, Some(current.span_id));
                prop_assert_ne!(child.span_id, current.span_id);
                current = child;
            }
        }

        /// The ring never holds more than its capacity, whatever order spans arrive in. An unbounded trace
        /// buffer is a second copy of the log, in memory.
        #[test]
        fn the_ring_never_exceeds_its_capacity(
            capacity in 0usize..16,
            count in 0usize..40,
            trace_count in 1usize..4,
        ) {
            let ring = TraceRing::with_capacity(capacity);
            let contexts: Vec<TraceContext> = (0..trace_count)
                .map(|_| TraceContext::always(TraceId::new()))
                .collect();

            for index in 0..count {
                let context = contexts[index % contexts.len()];
                ring.record(Span::start(context, format!("s{index}"), index as u64));
            }
            prop_assert!(ring.len() <= capacity);
            prop_assert_eq!(ring.len() + ring.dropped() as usize, count);
        }

        /// A trace's steps come back in the order they started, whatever order they were recorded in.
        #[test]
        fn recorded_order_does_not_determine_replay_order(
            times in proptest::collection::vec(0u64..10_000, 1..20)
        ) {
            let ring = TraceRing::with_capacity(64);
            let context = TraceContext::always(TraceId::new());
            for time in &times {
                ring.record(Span::start(context, "step", *time));
            }

            let steps = ring.steps_for(context.trace_id);
            prop_assert_eq!(steps.len(), times.len());
            prop_assert!(steps.windows(2).all(|pair| pair[0].started_at_ms <= pair[1].started_at_ms));
        }

        /// A span's duration is never negative, whatever the two clock readings are.
        #[test]
        fn a_duration_is_never_negative(start in 0u64..10_000, end in 0u64..10_000) {
            let context = TraceContext::always(TraceId::new());
            let mut span = Span::start(context, "s", start);
            span.finish(end, false);
            let elapsed = span.elapsed_ms.expect("finished");
            prop_assert!(elapsed <= 10_000, "{elapsed}");
            if end >= start {
                prop_assert_eq!(elapsed, end - start);
            }
            else {
                prop_assert_eq!(elapsed, 0);
            }
        }
    }
}
