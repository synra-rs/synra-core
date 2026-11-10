use serde::{Deserialize, Serialize};
use synra_protocol::{DeviceId, PluginId};

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
