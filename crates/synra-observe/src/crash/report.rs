use std::time::Duration;

use serde::{Deserialize, Serialize};
use synra_protocol::TraceId;

/// How long after a crash the report still counts as "the last run".
///
/// Five minutes, per the design document. A longer window would treat yesterday's crash as this morning's
/// and offer the user a prompt about something they already dealt with.
pub const RECENT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// What went wrong, as far as the process could tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashReport {
    /// When the crash happened, in milliseconds since the epoch.
    pub at_ms: i64,
    /// The application's version.
    pub version: String,
    /// Where it happened, as `file:line:column`, when the panic carried a location.
    ///
    /// This is the key the repeat count is kept on. A report without one cannot contribute to safe mode,
    /// which is deliberate: an unknown location is not evidence that the same bug happened again.
    pub location: Option<String>,
    /// The panic message, when it was a string.
    pub message: Option<String>,
    /// The thread's name, when it had one.
    pub thread: Option<String>,
    /// A captured backtrace.
    pub backtrace: Option<String>,
    /// The trace in progress, when the panic happened inside one.
    ///
    /// Recorded so a maintainer can find the steps that led here in the log, rather than guessing from the
    /// timestamp.
    pub trace_id: Option<TraceId>,
}

impl CrashReport {
    /// Builds a report from what a panic hook can see.
    ///
    /// Takes the pieces rather than the `PanicHookInfo` so the type is testable without inducing a panic,
    /// and so a caller that catches a `JoinHandle` error can build one from a different source.
    #[must_use]
    pub fn new(
        at_ms: i64,
        version: impl Into<String>,
        location: Option<String>,
        message: Option<String>,
        thread: Option<String>,
        backtrace: Option<String>,
        trace_id: Option<TraceId>,
    ) -> Self {
        Self {
            at_ms,
            version: version.into(),
            location,
            message,
            thread,
            backtrace,
            trace_id,
        }
    }

    /// Whether this crash is recent enough to be about the run that just ended.
    #[must_use]
    pub fn is_recent(&self, now_ms: i64) -> bool {
        let elapsed = now_ms.saturating_sub(self.at_ms);
        if elapsed < 0 {
            // A report from the future means the clock moved backwards — a suspend, a manual change. Treating
            // it as old would hide a crash; treating it as fresh is the safe direction.
            return true;
        }
        elapsed <= i64::try_from(RECENT_WINDOW.as_millis()).unwrap_or(i64::MAX)
    }

    /// The key the repeat count is kept on.
    #[must_use]
    pub fn location_key(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// A one-line summary for the prompt.
    #[must_use]
    pub fn summary(&self) -> String {
        let where_at = self.location.as_deref().unwrap_or("unknown location");
        let what = self.message.as_deref().unwrap_or("no message");
        format!("{what} (at {where_at})")
    }
}
