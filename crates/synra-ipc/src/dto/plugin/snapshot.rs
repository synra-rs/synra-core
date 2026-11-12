use serde::{Deserialize, Serialize};
use synra_protocol::PluginId;

/// A plugin, as a card in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSnapshot {
    /// The plugin.
    pub plugin_id: PluginId,
    /// Where this plugin's own data lives, for a screen that is about to delete it.
    ///
    /// ★ A path rather than a boolean: the removal dialog has two outcomes and one of them deletes this directory, so the
    /// user is entitled to see it before agreeing. The shell builds it from `Paths::plugin_sandbox_dir`, which is the
    /// same function the removal itself uses — two derivations of "where the data is" would be two answers to a question
    /// about deletion.
    #[serde(default)]
    pub data_path: String,
    /// Its name.
    pub title: String,
    /// Its description, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Its version.
    pub version: String,
    /// Whether the installed bytes come from a local directory.
    pub local_source: bool,
    /// Who published it.
    pub publisher: String,
    /// Whether it is enabled.
    pub enabled: bool,
    /// Where it is in its life. `snake_case`, matching the kernel's own states.
    ///
    /// The interface shows this rather than deriving a state from `enabled` and a health field: a plugin that is
    /// enabled but faulted is a state the user has to be told about, and deriving it in the interface would mean
    /// two implementations of the same rule.
    pub state: String,
    /// Why it is not running, when the host knows a reason the state word cannot carry.
    ///
    /// ★ The state word says *what* (`unavailable`, `unreadable`); this says *why*, in the sentence the layer that
    /// decided produced. Safe mode is the case that made it necessary: every plugin is `unavailable` because the host
    /// chose not to start any of them after a crash loop, and a user who is told only "unavailable" goes looking for a
    /// broken plugin instead of the crash they need to see.
    ///
    /// Omitted rather than `null` when there is nothing to say, so "no reason recorded" and "the host had no reason"
    /// are the same absent field the page already handles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_reason: Option<String>,
    /// Whether it has both halves.
    pub hybrid: bool,
    /// Whether it has a page of its own.
    ///
    /// ★ Apart from [`Self::hybrid`], which means **both** halves. A UI-only plugin has a page and no headless half, and
    /// a card that offered "open" only for a hybrid plugin would leave that one with no way in at all.
    pub has_ui: bool,
    /// How much of its quota it is using, for the settings screen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<PluginHealthDto>,
    /// The capabilities the plugin **declares**, whether or not the user has decided about them.
    ///
    /// ★ Why this is not derivable from `granted` + `denied`: before the prompt has been answered both are empty, and
    /// the prompt itself is "decide about *these*". Without it the interface can only offer "allow everything", which
    /// is the decision per-capability consent exists to avoid making on the user's behalf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested: Vec<String>,
    /// The capabilities the user granted.
    #[serde(default)]
    pub granted: Vec<String>,
    /// The capabilities the user denied.
    ///
    /// `default` as well as `skip_serializing_if`, because a plugin whose every capability was granted serialises
    /// no `denied` field at all — and without the default the interface could not read back what it wrote.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,
    /// Whether an update is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateInfo>,
    /// When this installed version was last successfully checked, in milliseconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_checked_at_ms: Option<i64>,
}

/// How a plugin is behaving, for the transparency the design document requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginHealthDto {
    /// Where it sits on the escalation ladder. `snake_case`.
    pub health: String,
    /// A sentence explaining it.
    ///
    /// ★ A sentence rather than a message key, which is what this field used to claim: the quota's `Health::explain` returns
    /// prose from a stable crate, and calling it a key made the interface look like it could translate something it cannot.
    pub explanation: String,
    /// How many host calls it has made.
    pub calls_admitted: u64,
    /// How many were refused.
    pub calls_refused: u64,
    /// What it is using, by resource.
    pub usage: serde_json::Value,
}

/// An available update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// Which plugin the update is for.
    ///
    /// ★ Carried rather than inferred from the call: the background pass reports several at once, and a list of versions
    /// with no plugin attached would need a second shape to say what each one belongs to.
    pub plugin_id: PluginId,
    /// The version on offer.
    pub version: String,
    /// Whether its manifest asks for something the current one did not.
    ///
    /// What the interface uses to say "this update wants a new permission" rather than "an update is available":
    /// the second is a routine message and the first is a decision.
    pub needs_new_consent: bool,
    /// Which capabilities are new.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added_capabilities: Vec<String>,
}

/// A publisher whose signature this device has seen.
///
/// The key material is not here: a screen shows the **fingerprint**, which is what a person compares, and the installer
/// reads the key from the table when it verifies a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublisherDto {
    /// The publisher's own identifier, from its signature.
    pub publisher_id: String,
    /// The key's fingerprint, grouped for a person to read.
    pub fingerprint: String,
    /// `seen`, `trusted` or `revoked`.
    pub trust: String,
    /// When a signature from this key was first seen.
    pub first_seen_ms: i64,
    /// When the user decided, if they have.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_ms: Option<i64>,
}
