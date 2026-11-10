use serde::{Deserialize, Serialize};
use synra_protocol::PluginId;

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
