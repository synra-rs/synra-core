//! How a plugin was stopped, and how many stops make a version unstable.

use serde::{Deserialize, Serialize};

/// How many unexpected stops make a version unstable.
pub const UNSTABLE_THRESHOLD: u32 = 3;

/// How a plugin was stopped, for the health history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopRecord {
    /// The version that was running.
    pub version: String,
    /// How many times this version has stopped unexpectedly.
    pub unexpected_stops: u32,
    /// The most recent reason.
    pub last_reason: Option<String>,
}

impl StopRecord {
    /// A record for a version that has not stopped.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self { version: version.into(), unexpected_stops: 0, last_reason: None }
    }

    /// Records a stop the host did not choose.
    ///
    /// Only unexpected stops count. Counting a user deactivating a plugin would fault it for being switched off.
    pub fn record_unexpected_stop(&mut self, reason: impl Into<String>) {
        self.unexpected_stops = self.unexpected_stops.saturating_add(1);
        self.last_reason = Some(reason.into());
    }

    /// Whether the plugin has stopped unexpectedly too often to keep loading it.
    ///
    /// Three, matching the crash-driven safe mode in the observability design: a plugin that has crashed three times
    /// in a row is not going to work on the fourth.
    #[must_use]
    pub const fn is_unstable(&self) -> bool {
        self.unexpected_stops >= UNSTABLE_THRESHOLD
    }
}
