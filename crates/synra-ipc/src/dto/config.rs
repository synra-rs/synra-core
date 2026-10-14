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
