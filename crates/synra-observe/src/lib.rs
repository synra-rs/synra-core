//! Observability: logging, tracing, metrics, audit and diagnostics.
//!
//! Three questions, and this crate answers all three without the answers leaking into each other:
//!
//! * **What happened?** — logs, spans and crash reports.
//! * **How much of it?** — metrics, with cardinality bounded.
//! * **What was the software allowed to do, and what did it do?** — the audit trail.
//!
//! Plus the thing a user actually sends when they ask for help: the diagnostic bundle.
//!
//! # Nothing here is a data channel
//!
//! There is no HTTP exporter, no beacon, no background upload. Metrics live in memory and exist so the
//! settings screen can draw a graph and a diagnostic bundle can carry a snapshot. That is a design
//! decision rather than an unfinished feature: a desktop application that ships a user's file-transfer
//! statistics to somebody else's server has to earn that, and the way to earn it is to not need it.
//!
//! # Redaction is a policy, not a filter
//!
//! [`redact`] holds the list of what must never be written down, and it is applied by the log layer, the
//! diagnostic bundle and any error a user might paste into an issue — one implementation, so the three
//! cannot drift apart. A filter that dropped whole log lines would lose the diagnosis along with the
//! secret; this keeps the line and drops the value.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod crash;
pub mod logging;
pub mod metrics;
pub mod redact;
pub mod trace;

pub use crash::{CrashReport, CrashStore, StartupVerdict};
pub use logging::{LogLevel, RedactingWriter, Verbosity};
pub use metrics::{CardinalityGuard, HistogramSnapshot, MetricsSnapshot, RingRecorder, SeriesKey};
pub use redact::{REDACTED, Redacted, Redaction, Redactor};
pub use trace::{Sampler, Span, SpanId, TraceContext, TraceOrigin, TraceRing};
