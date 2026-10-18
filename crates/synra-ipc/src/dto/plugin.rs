//! Plugins: what is installed, what is available, and what installing one reports.

use serde::{Deserialize, Serialize};

use synra_protocol::{DeviceId, PluginId};

// ─────────────────────────────────────────────────────────────────────────────
// Plugins
// ─────────────────────────────────────────────────────────────────────────────

/// A plugin, as a card in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSnapshot {
    /// The plugin.
    pub plugin_id: PluginId,
    /// Its name.
    pub title: String,
    /// Its description, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Its version.
    pub version: String,
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
}

/// How a plugin is behaving, for the transparency the design document requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginHealthDto {
    /// Where it sits on the escalation ladder. `snake_case`.
    pub health: String,
    /// A message key explaining it.
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

/// A plugin in the catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogItem {
    /// The plugin's identifier.
    pub plugin_id: PluginId,
    /// Its name.
    pub title: String,
    /// Its description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The version on offer.
    pub version: String,
    /// Who published it.
    pub publisher: String,
    /// How many capabilities it asks for.
    ///
    /// A count rather than the list: the catalogue response is a search result, and a search result that carried
    /// every plugin's full permission list would be the largest thing on the wire for the least read part of it.
    pub capability_count: usize,
    /// Whether it is already installed.
    pub installed: bool,
}

/// How a catalogue result set is ordered.
///
/// ★ Only the two the search endpoint can honour: npm's index returns relevance, and the rest of the design's sorts
/// (downloads, updated) are numbers the search response does not carry. A `sort` value this build cannot perform is not
/// offered rather than silently ignored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum CatalogSort {
    /// The registry's own order, which for an npm index is relevance.
    #[default]
    Relevance,
    /// By name, for a list a person is scanning.
    Name,
}

/// What to search the catalogue for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogQuery {
    /// The search text.
    pub query: String,
    /// Which registry, when the user has more than one configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// The most results to return. The kernel clamps this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// How many results to skip, for paging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// The order to return them in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<CatalogSort>,
}

/// Where a plugin is being installed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "source")]
#[non_exhaustive]
pub enum InstallSourceDto {
    /// A path the user chose.
    Path {
        /// The path.
        path: String,
    },
    /// A package from a registry.
    Registry {
        /// The plugin.
        plugin_id: PluginId,
        /// The version, or the latest when absent.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
}

/// What an install did.
///
/// # Why this is not a [`PluginSnapshot`]
///
/// Because the two answer different questions: a snapshot describes a plugin that exists, and this describes an act that
/// just happened — including what a user has to be **told**. A plugin that installed but whose notification action this
/// host cannot perform is a warning, and a report that dropped it would present a plugin that half-works as one that
/// works.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallReport {
    /// The plugin that is now installed.
    pub plugin_id: PluginId,
    /// The version that landed.
    pub version: String,
    /// The checks that passed with a warning, in sentences an interface can show.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Whether it is enabled. **Always `false` from an install**: installing is not approving, and the field is here so
    /// that a caller cannot read its absence as "it is probably on".
    pub enabled: bool,
    /// Who signed the package, when it carried a genuine signature.
    ///
    /// The pair is the question the interface asks next: "this key signed it — do you trust the key?". Absent means the
    /// package was unsigned, which is the ordinary case for a local build.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    /// The signing key's fingerprint, when there was a signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// What a registry package would install, before any of it is downloaded.
///
/// ★ Read from the packument's inline manifest (16 §4.1), which is the publisher's claim and not yet a verified fact: the
/// signature check happens on the bytes. A preview is a question — "these are the permissions it asks for, do you want to
/// fetch and install it?" — not an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallPreviewDto {
    /// The plugin the package would install.
    pub plugin_id: PluginId,
    /// The version that would be installed.
    pub version: String,
    /// The name shown to a person.
    pub title: String,
    /// A sentence describing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The publisher's identifier.
    pub publisher: String,
    /// A name to show, when the manifest has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_name: Option<String>,
    /// The fingerprint a static directory lists for the publisher, when it lists one.
    ///
    /// ★ A claim beside the index, not a verification: the signature is checked on the downloaded bytes, and this gives the
    /// dialog a second statement to compare that result with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_key: Option<String>,
    /// What it asks to be allowed, as the manifest spells it.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Whether it runs without an interface.
    pub headless: bool,
    /// Whether it adds pages to the interface.
    pub has_ui: bool,
    /// The published size in bytes, when the packument states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// What to do with the plugin's data when removing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveOptionsDto {
    /// Whether to delete the plugin's data and its sandbox.
    ///
    /// Two steps rather than one because they are different decisions: removing a plugin the user may reinstall
    /// should keep its settings, and removing one they do not trust should not.
    pub remove_data: bool,
}

/// What removing a plugin did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveReport {
    /// How many bytes of the plugin's data were freed.
    pub bytes_freed: u64,
    /// Whether the data was kept.
    pub data_kept: bool,
    /// Whatever could not be removed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub leftovers: Vec<String>,
}

/// How a plugin would be synchronised to other devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPlanDto {
    /// The plugin.
    pub plugin_id: PluginId,
    /// The devices it would go to, and what each needs.
    pub targets: Vec<SyncTarget>,
}

/// One device a synchronisation would reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTarget {
    /// The device.
    pub device_id: DeviceId,
    /// Its name.
    pub display_name: String,
    /// Whether it needs the artifact sent.
    pub needs_artifact: bool,
    /// What it already has, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether it can be reached now.
    pub online: bool,
}

/// What a synchronisation did.
///
/// Not `Eq`, because its failures carry an [`crate::IpcError`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    /// How many devices were brought up to date.
    pub updated: u32,
    /// How many were already current.
    pub unchanged: u32,
    /// The devices that failed, with their reasons.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<SyncFailure>,
}

/// One device a synchronisation could not reach.
///
/// Not `Eq`, because it carries an [`crate::IpcError`] whose parameters are a JSON value — and a JSON value
/// containing a float has no total equality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncFailure {
    /// The device.
    pub device_id: DeviceId,
    /// Why.
    pub error: crate::IpcError,
}

/// One entry from a plugin's audit trail.
///
/// There is deliberately no content field: the design document forbids payloads in an audit record, and the
/// absence of a field is what enforces it rather than a rule someone has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntryDto {
    /// When it happened.
    pub at_ms: i64,
    /// What was attempted.
    pub capability: String,
    /// Whether it was allowed.
    pub allowed: bool,
    /// Why not, when it was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How long the call took.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    /// The trace it belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}
