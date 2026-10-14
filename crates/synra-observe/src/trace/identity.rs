use serde::{Deserialize, Serialize};

use synra_protocol::TraceId;
use synra_protocol::envelope::Envelope;

use super::sampler::Sampler;

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
