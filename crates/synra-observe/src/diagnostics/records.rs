//! The records a bundle is made of.
//!
//! # Why every section is an `Option`
//!
//! Because "not collected" and "collected and empty" are different answers. An empty list of plugins reads as "no
//! plugins installed"; `None` reads as "this was not gathered", which is what a reader needs in order to know whether
//! an absence is information.

use serde::{Deserialize, Serialize};

use crate::audit::AuditEntry;
use crate::doctor::ProbeResult;
use crate::metrics::MetricsSnapshot;

use super::digest::sha256_hex;
use super::sections::{BundleSection, NEVER_INCLUDED};

/// Where a bundle's sections came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvSummary {
    /// The application's version.
    pub app_version: String,
    /// The kernel's version, so a protocol mismatch is visible without asking.
    pub kernel_version: String,
    /// The operating system, as the platform reported it.
    pub os: String,
    /// The architecture.
    pub arch: String,
    /// The WebView's version, when it was readable.
    pub webview_version: Option<String>,
}

/// A log line in a bundle, already redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleLogLine {
    /// The line's own text, with secrets removed.
    pub text: String,
    /// Whether the tail was cut because the line was too long.
    pub truncated: bool,
}

/// The log slice a bundle carries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSlice {
    /// The last lines of the log, oldest first.
    pub tail: Vec<BundleLogLine>,
    /// Every error-level line found, even outside the tail.
    pub errors: Vec<BundleLogLine>,
    /// How many lines were read.
    pub lines_read: usize,
    /// How many lines were left out.
    pub lines_omitted: usize,
}

/// Whether a device is reachable, as the bundle records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    /// The device's id, as text.
    pub device_id: String,
    /// Whether it is paired.
    pub paired: bool,
    /// Whether a link is up right now.
    pub online: bool,
}

/// A plugin's state, as the bundle records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRecord {
    /// The plugin's id.
    pub plugin_id: String,
    /// Its version.
    pub version: String,
    /// Whether it is currently loaded.
    pub active: bool,
    /// Whether any of its capabilities were refused.
    ///
    /// A boolean rather than the records themselves: this section is not optional, so it must not carry the
    /// audit trail's detail. The count is what a maintainer needs to know to ask for the trail.
    pub had_refusals: bool,
}

/// Everything a bundle can hold.
///
/// One optional field per section, so a section that was not selected is `None` rather than an empty list. The
/// difference matters: an empty list of plugins reads as "no plugins installed", and `None` reads as "not
/// collected", which is what a reader needs in order to know whether the absence is information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticBundle {
    /// When the bundle was assembled, in milliseconds since the epoch.
    pub generated_at_ms: i64,
    /// Which sections are present, for a reader that wants the list before the contents.
    pub sections: Vec<String>,
    /// What is never included, carried in the file itself.
    ///
    /// The consent screen shows this list, and so does the bundle: a maintainer reading the file should see the
    /// same promise the user agreed to, rather than having to trust that the screen said it.
    pub excluded: Vec<String>,
    /// The environment summary.
    pub environment: Option<EnvSummary>,
    /// The configuration, already redacted.
    pub config: Option<serde_json::Value>,
    /// Paired devices and their state.
    pub devices: Option<Vec<DeviceRecord>>,
    /// Installed plugins and their state.
    pub plugins: Option<Vec<PluginRecord>>,
    /// Counter and histogram values.
    pub metrics: Option<MetricsSnapshot>,
    /// The log slice.
    pub logs: Option<LogSlice>,
    /// Recent crash reports.
    pub crashes: Option<Vec<crate::crash::CrashReport>>,
    /// Environment probe results.
    pub probes: Option<Vec<ProbeResult>>,
    /// The audit trail.
    pub audit_trail: Option<Vec<AuditEntry>>,
}

impl DiagnosticBundle {
    /// An empty bundle.
    #[must_use]
    pub fn empty(generated_at_ms: i64) -> Self {
        Self {
            generated_at_ms,
            sections: Vec::new(),
            excluded: NEVER_INCLUDED.iter().map(|item| (*item).to_owned()).collect(),
            environment: None,
            config: None,
            devices: None,
            plugins: None,
            metrics: None,
            logs: None,
            crashes: None,
            probes: None,
            audit_trail: None,
        }
    }

    /// Whether a section is present.
    #[must_use]
    pub fn contains(&self, section: BundleSection) -> bool {
        self.sections.iter().any(|name| name == section.as_str())
    }

    /// How many sections are present.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sections.len()
    }

    /// Whether the bundle holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// The bundle as pretty JSON.
    ///
    /// Pretty rather than compact because a person reads this file — that is the whole point of a bundle
    /// somebody chose to export — and a reader who opens it should not be looking at one line of eight thousand
    /// characters.
    ///
    /// # Errors
    ///
    /// A serialisation error, which would mean a type in the bundle is not serialisable.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// The SHA-256 of the rendered JSON.
    ///
    /// Reported to the user after an export so they can check that what they uploaded is what they reviewed.
    /// Nothing in the application verifies it.
    ///
    /// # Errors
    ///
    /// As [`Self::to_json`].
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        Ok(sha256_hex(self.to_json()?.as_bytes()))
    }
}
