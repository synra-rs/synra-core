use serde::{Deserialize, Serialize};
use synra_protocol::ids::SessionId;
use synra_protocol::{DeviceId, PluginId};

/// Receiver-side session phase. Every new controller starts at Pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    /// Waiting for a local person.
    Pending,
    /// Accepted locally; native initialization is in progress.
    Allowed,
    /// Receiving real pointer input.
    Active,
    /// Refused, stopped, revoked, expired or disconnected.
    Ended,
}

/// Bounded state for the receiver's consent prompt and active indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Receiver-issued session handle.
    pub session: SessionId,
    /// The peer established by Hello.
    pub peer: DeviceId,
    /// Local recorded device name.
    pub peer_name: String,
    /// The full plugin identity.
    pub plugin_id: PluginId,
    /// Current control state.
    pub phase: Phase,
    /// Structured lifecycle reason, without input contents.
    pub reason: Option<String>,
}
