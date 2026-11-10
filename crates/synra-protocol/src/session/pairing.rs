use core::fmt;
use core::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::SynraError;
use crate::ids::{DeviceId, IntentId, PluginId};
use crate::limits;

/// Timeouts for every kind of session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimeouts {
    /// How long a pairing request may wait for an answer.
    pub pairing: Duration,
    /// How long an intent may run, end to end.
    pub intent: Duration,
    /// How long a transfer may go without receiving a block before it is abandoned.
    pub transfer_idle: Duration,
    /// How long a transfer may run in total, however active it is.
    pub transfer_total: Duration,
    /// How long a finished session's result is kept, so a retry can be answered without re-running.
    pub result_cache: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            pairing: Duration::from_secs(30),
            intent: Duration::from_secs(30),
            transfer_idle: Duration::from_secs(60),
            transfer_total: Duration::from_secs(30 * 60),
            result_cache: Duration::from_secs(5 * 60),
        }
    }
}

impl SessionTimeouts {
    /// Rejects a combination that cannot work.
    ///
    /// Checked rather than assumed because both mistakes below are silent. A result cache shorter
    /// than the dedup window means a retry re-executes work the user already waited for; an idle
    /// timeout longer than the total one means the idle check can never fire, so a stalled transfer
    /// is only caught by the total timeout — minutes later, with no progress reported in between.
    ///
    /// # Errors
    ///
    /// Describes the first inconsistency found.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pairing.is_zero() || self.intent.is_zero() {
            return Err("pairing and intent timeouts must be non-zero, or every session hangs");
        }
        if self.transfer_total < self.transfer_idle {
            return Err("transfer_total must be at least transfer_idle, or the idle check never fires");
        }
        // A retry arrives within the dedup window, so the cached answer has to outlive it.
        if self.result_cache < limits::REQUEST_DEDUP_WINDOW {
            return Err("result_cache must cover the request dedup window, or a retry re-runs the work");
        }
        Ok(())
    }
}

/// Which platform a device runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlatformKind {
    /// Windows, macOS or Linux.
    Desktop,
    /// Android.
    Android,
    /// iOS.
    Ios,
}

impl PlatformKind {
    /// Whether this is a mobile platform, where the host may be suspended at any moment.
    #[must_use]
    pub const fn is_mobile(self) -> bool {
        matches!(self, Self::Android | Self::Ios)
    }
}

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Desktop => "desktop",
            Self::Android => "android",
            Self::Ios => "ios",
        })
    }
}

/// What a peer is told about a device during pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerProfile {
    /// The device's stable id.
    pub device_id: DeviceId,
    /// The name to show a human.
    pub display_name: String,
    /// Which platform, so the interface can pick an icon and hide what is unsupported.
    pub platform: PlatformKind,
    /// The host application's version.
    pub app_version: String,
}

impl PeerProfile {
    /// The longest display name accepted, so a peer cannot fill the interface with one string.
    pub const MAX_DISPLAY_NAME: usize = 64;

    /// Checks the profile is usable.
    ///
    /// # Errors
    ///
    /// A description of what is wrong.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.device_id.is_nil() {
            return Err("device_id must not be nil");
        }
        if self.display_name.trim().is_empty() {
            return Err("display_name must not be blank");
        }
        // Counted in characters, not bytes: a name in CJK is not "too long" in a unit the user
        // cannot see.
        if self.display_name.chars().count() > Self::MAX_DISPLAY_NAME {
            return Err("display_name is too long");
        }
        if self.app_version.trim().is_empty() {
            return Err("app_version must not be blank");
        }
        Ok(())
    }
}

/// An action this device is asking another device to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentInvocation {
    /// Identifies this intent across both devices.
    pub intent_id: IntentId,
    /// Which plugin should run it.
    pub plugin_id: PluginId,
    /// Which of that plugin's actions.
    pub action: String,
    /// The action's arguments, as raw JSON.
    ///
    /// Unparsed here for the same reason an envelope's payload is: the receiving kernel validates it
    /// against the plugin's declared schema and does not need to understand it first.
    pub args: Box<RawValue>,
    /// Text the interface may show when asking the user to confirm.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display: Option<IntentDisplay>,
}

impl PartialEq for IntentInvocation {
    /// Compares `args` by value rather than by spelling: see [`crate::envelope`]'s note on why
    /// `RawValue` needs a hand-written comparison.
    fn eq(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.plugin_id == other.plugin_id
            && self.action == other.action
            && self.display == other.display
            && crate::envelope::raw_json_eq(Some(&self.args), Some(&other.args))
    }
}

impl Eq for IntentInvocation {}

/// What the interface shows while asking the user to confirm a remote action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentDisplay {
    /// One line, such as "Open this link".
    pub title: String,
    /// Optional detail, such as the URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
    /// Which device is asking. Shown because "who wants this" is part of the decision.
    pub source_display_name: String,
}

/// How an intent ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentOutcome {
    /// Which intent this concludes.
    pub intent_id: IntentId,
    /// Whether it worked.
    pub ok: bool,
    /// The action's return value, when it succeeded and produced one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Box<RawValue>>,
    /// The failure, when it did not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<SynraError>,
    /// How long the action took on the remote device.
    pub elapsed_ms: u64,
}

impl PartialEq for IntentOutcome {
    fn eq(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.ok == other.ok
            && self.error == other.error
            && self.elapsed_ms == other.elapsed_ms
            && crate::envelope::raw_json_eq(self.result.as_deref(), other.result.as_deref())
    }
}

impl Eq for IntentOutcome {}

impl IntentOutcome {
    /// A successful outcome.
    #[must_use]
    pub const fn ok(intent_id: IntentId, result: Option<Box<RawValue>>, elapsed_ms: u64) -> Self {
        Self { intent_id, ok: true, result, error: None, elapsed_ms }
    }

    /// A failed outcome.
    ///
    /// An outcome is either a result or an error, never both: an interface that had to decide which
    /// of the two to believe would eventually meet a case where they disagree.
    #[must_use]
    pub const fn failed(intent_id: IntentId, error: SynraError, elapsed_ms: u64) -> Self {
        Self { intent_id, ok: false, result: None, error: Some(error), elapsed_ms }
    }

    /// Checks the shape is self-consistent.
    ///
    /// # Errors
    ///
    /// A description of what is wrong.
    pub const fn validate(&self) -> Result<(), &'static str> {
        match (self.ok, &self.error) {
            (true, Some(_)) => Err("a successful outcome must not carry an error"),
            (false, None) => Err("a failed outcome must carry an error"),
            _ => Ok(()),
        }
    }
}
