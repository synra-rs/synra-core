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

mod identity;
mod ring;
mod sampler;
mod span;

pub use identity::{SpanId, TraceContext, TraceOrigin};
pub use ring::TraceRing;
pub use sampler::{DEFAULT_ALWAYS_SLOWER_THAN_MS, DEFAULT_BASE_RATE_PPM, Sampler};
pub use span::{Span, render_trace};

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod tests;
