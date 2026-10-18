//! Configuration and diagnostics: what the settings screens read, and what a bundle would contain.

use serde::{Deserialize, Serialize};


// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The configuration, as the settings screens read it.
///
/// A free-form JSON object rather than a struct with a field per setting. The reason is that the configuration
/// grows with every feature and a struct here would mean an interface release for every kernel release — so the
/// boundary carries the bag and the *screens* own their own shape, which is where the knowledge of what a
/// setting means actually lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSnapshot {
    /// Every setting, keyed by its dotted path.
    pub values: serde_json::Value,
    /// Which keys came from a file rather than the defaults, for the screen to mark.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub overridden: Vec<String>,
}

/// A change to the configuration.
///
/// Keys rather than a whole replacement, because two screens can be open and a whole-value write from one would
/// discard the other's change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigPatch {
    /// The keys to set.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub set: serde_json::Map<String, serde_json::Value>,
    /// The keys to remove, returning them to their defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset: Vec<String>,
}

impl ConfigPatch {
    /// Whether it would change anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.unset.is_empty()
    }

    /// How many keys it touches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len() + self.unset.len()
    }

    /// Whether a key is both set and unset.
    ///
    /// Refused rather than resolved by precedence: the caller meant one of the two, and picking for them produces
    /// a setting that is the opposite of what they asked for half the time.
    #[must_use]
    pub fn has_conflict(&self) -> Option<&str> {
        self.unset
            .iter()
            .find(|key| self.set.contains_key(key.as_str()))
            .map(String::as_str)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics
// ─────────────────────────────────────────────────────────────────────────────

/// What to put in a diagnostic bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagExportOptions {
    /// Whether to include the audit trail. Default off, because it names the plugins the user runs.
    pub include_audit: bool,
    /// Whether to include debug-level log lines. Default off, because they are the most likely to contain
    /// something the user did not intend to share.
    pub include_debug_logs: bool,
    /// How many log lines to include.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_lines: Option<u32>,
}

/// What a diagnostic export wrote.
///
/// ★ This used to live in the shell's own `commands::diag`, which made it a shape only the Rust side knew: the page
/// that offers the button had to copy it by hand, and a hand-written copy does not fail to compile when the kernel adds
/// a field. `included` and `excluded` are what the confirmation screen shows back, so they are part of the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagExportResult {
    /// The file that was written.
    pub path: String,
    /// Which sections it holds.
    pub included: Vec<String>,
    /// Which sections were left out, and why.
    pub excluded: Vec<String>,
}

/// One startup probe's result, as the interface shows it.
///
/// `status` is a string (`ok`/`warn`/`fail`) rather than the observation crate's enum: this is the boundary, and a DTO
/// that reused the enum would put `synra-observe` in the contract's type mirror for one field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResultDto {
    /// A stable machine-readable name, such as `tcp_port_available`.
    pub name: String,
    /// `ok`, `warn` or `fail`.
    pub status: String,
    /// What was found, in a sentence.
    pub detail: String,
    /// What to do about it, when there is something to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// Every probe the shell ran, in the order it ran them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReportDto {
    /// The results.
    pub results: Vec<ProbeResultDto>,
}
