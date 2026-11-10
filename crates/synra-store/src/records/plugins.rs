//! Plugin state, actions and grant rows.

use serde::{Deserialize, Serialize};

use super::{required, to_bool, RowError};

/// A plugin the kernel knows about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRow {
    /// The plugin's identifier.
    pub plugin_id: String,
    /// Whether it is allowed to run.
    pub enabled: bool,
    /// Whether the user has confirmed what it may do.
    ///
    /// Separate from `enabled` because the two answer different questions, and collapsing them would make "turn this off
    /// for a moment" the same act as "I no longer trust this".
    pub trusted: bool,
    /// What the host last observed.
    ///
    /// A string, because `plugin_versions` and the host's health vocabulary are theirs; the column is `TEXT NOT NULL
    /// DEFAULT 'unknown'` and the kernel compares it, so an unexpected value is a health state rather than a parse error.
    pub health: String,
    /// When it was installed.
    pub installed_at_ms: i64,
    /// When it was last updated.
    pub updated_at_ms: i64,
}

impl PluginRow {
    /// Builds a row from the columns `plugins` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError`] when a `NOT NULL` column is empty or a boolean column holds something else.
    pub fn from_columns(
        plugin_id: Option<&str>,
        enabled: Option<i64>,
        trusted: Option<i64>,
        health: Option<&str>,
        installed_at_ms: Option<i64>,
        updated_at_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            plugin_id: required(plugin_id, "plugin_id")?.to_owned(),
            enabled: to_bool(enabled, "enabled")?,
            trusted: to_bool(trusted, "trusted")?,
            health: required(health, "health")?.to_owned(),
            installed_at_ms: required(installed_at_ms, "installed_at_ms")?,
            updated_at_ms: required(updated_at_ms, "updated_at_ms")?,
        })
    }

    /// Whether the kernel would load it.
    ///
    /// Both conditions, because a plugin the user has confirmed but switched off is not one to load — and a plugin that
    /// is on but never trusted is one whose capabilities nobody approved.
    #[must_use]
    pub const fn should_run(&self) -> bool {
        self.enabled && self.trusted
    }
}

/// One action a plugin has declared, as `plugin_actions` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginActionRow {
    /// The action's name, unique within the plugin.
    ///
    /// The name is what the page passes to `self.invoke`, so it is the identity of the action rather than a label: two
    /// declarations under one name are one action, and the later schema replaces the earlier.
    pub name: String,
    /// The JSON Schema of its arguments, when it declared one.
    ///
    /// Stored as the text the plugin sent rather than parsed, because this table's job is to remember the declaration;
    /// a schema is read by an interface that wants to render a form, not by the kernel.
    pub args_schema: Option<String>,
    /// What it does, when the plugin said.
    pub description: Option<String>,
}

/// One capability's decision, as `plugin_grants` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginGrantRow {
    /// The capability.
    pub capability: String,
    /// Whether the user allowed it.
    pub granted: bool,
    /// When the decision was made.
    pub decided_ms: i64,
    /// The manifest it was made against.
    ///
    /// Carried rather than recomputed because the whole purpose is to notice that the manifest has *changed* since — and
    /// recomputing it from the current manifest would compare the manifest against itself and always agree. An upgrade
    /// whose digest differs is a request for consent again, and a caller cannot detect that from the capability list: a
    /// plugin that declares a capability the user had already refused looks unchanged from the list.
    pub manifest_digest: String,
}

impl PluginGrantRow {
    /// Builds a row from the columns `plugin_grants` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError`] when a `NOT NULL` column is empty or the `granted` column holds something other than 0 or 1.
    pub fn from_columns(
        capability: Option<&str>,
        granted: Option<i64>,
        decided_ms: Option<i64>,
        manifest_digest: Option<&str>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            capability: required(capability, "capability")?.to_owned(),
            granted: to_bool(granted, "granted")?,
            decided_ms: required(decided_ms, "decided_ms")?,
            manifest_digest: required(manifest_digest, "manifest_digest")?.to_owned(),
        })
    }
}


