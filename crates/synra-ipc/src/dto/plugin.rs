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
    /// How much of its quota it is using, for the settings screen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<PluginHealthDto>,
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
