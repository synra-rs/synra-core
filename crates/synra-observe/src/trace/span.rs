use serde::{Deserialize, Serialize};

use super::identity::TraceContext;

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
