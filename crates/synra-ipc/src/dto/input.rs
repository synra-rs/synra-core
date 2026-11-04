//! Host-only pointer consent and control state; plugin pages cannot answer these decisions.
use serde::{Deserialize, Serialize};
use synra_protocol::ids::{DeviceId, PluginId, SessionId};

/// Receiver lifecycle, independent of a durable device pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InputPhase {
    /// A local user must decide.
    Pending,
    /// Native pointer initialization after acceptance.
    Starting,
    /// A leased controller is active.
    Active,
    /// The controller has been refused, stopped, revoked or disconnected.
    Ended,
}

/// One incoming input request or active control session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputSession {
    /// Receiver-issued handle required for host decisions.
    pub session_id: SessionId,
    /// Paired controller identity, taken from the peer link.
    pub device_id: DeviceId,
    /// Local device name.
    pub display_name: String,
    /// The full installed plugin identity whose receiver grant was checked.
    pub plugin_id: PluginId,
    /// Current state.
    pub phase: InputPhase,
    /// Terminal reason, without recorded pointer contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Complete state for the global consent prompt and active indicator.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputSnapshot {
    /// Absent before any request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<InputSession>,
}
