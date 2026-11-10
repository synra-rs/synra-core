use serde::{Deserialize, Serialize};

use crate::dto::{
    DeviceCard, IntentSnapshot, PluginSnapshot, ScanState, TransferSnapshot, UpdateInfo,
};
use synra_protocol::{DeviceId, IntentId, PluginId, TransferId};

/// One frame on or off the wire, for the debug console.
///
/// Carries no payload: the console is a transport view, and a payload would turn a debug feature into a second copy of
/// every message — including the ones a transfer spends its bandwidth on. Event name and size are what a reader needs to
/// see a conversation happen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugWire {
    /// When it happened, milliseconds since the epoch.
    pub at_ms: i64,
    /// `sent`, `received` or `note`.
    pub direction: String,
    /// The device on the other end, or `local` for a note.
    pub peer: String,
    /// An event name, `chunk #n`, or a note's short label.
    pub label: String,
    /// Payload bytes. Zero for a note.
    pub bytes: u64,
}

/// A change the interface should apply.
///
/// Internally tagged with `type`, so the interface's `switch` is exhaustive over a closed set and a variant it
/// does not know is a compile error rather than a case that never runs — except across a version skew, where the
/// `default` branch is what asks for a fresh snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "payload")]
#[non_exhaustive]
pub enum KernelEvent {
    // ── Devices ──
    /// A device card changed. Upsert by `deviceId`.
    DeviceCardUpdated(Box<DeviceCard>),
    /// A device is gone from the list, because it was forgotten or blocked.
    DeviceRemoved {
        /// Which device.
        device_id: DeviceId,
    },
    /// A discovery scan started, progressed or finished.
    ScanUpdated(Box<ScanState>),

    // ── Pairing ──
    /// Progress of the shared restricted first-pairing task, never an authorization grant.
    PairingUpdated(Box<crate::PairingSnapshot>),
    /// An incoming pointer request or active session changed; only host UI can decide or stop it.
    InputUpdated(Box<crate::InputSnapshot>),

    // ── Intent ──
    /// An intent's state changed, including its candidates becoming available.
    IntentUpdated(Box<IntentSnapshot>),
    /// An intent is over, whatever the outcome.
    IntentFinished {
        /// Which intent.
        intent_id: IntentId,
    },

    // ── Configuration ──
    /// The configuration changed, in full.
    ///
    /// Carries the whole snapshot rather than the patch that produced it: the patch is the caller's own input, and a
    /// reader that reassembled the two would be re-deriving what the kernel already knows.
    ConfigUpdated(Box<crate::dto::ConfigSnapshot>),

    // ── Transfers ──
    /// A transfer's progress or state changed.
    TransferUpdated(Box<TransferSnapshot>),
    /// A transfer is over, whatever the outcome.
    TransferFinished {
        /// Which transfer.
        transfer_id: TransferId,
    },

    // ── Plugins ──
    /// A plugin was installed, removed, enabled, disabled or faulted.
    PluginUpdated(Box<PluginSnapshot>),
    /// A plugin is being installed, and this much of it has arrived.
    PluginInstallProgress {
        /// Which plugin.
        plugin_id: PluginId,
        /// How far along, from `0` to `1`.
        progress: f64,
        /// What stage it is at, as a message key.
        stage: String,
    },
    /// An update became available for a plugin.
    PluginUpdateAvailable {
        /// Which plugin.
        plugin_id: PluginId,
        /// What is on offer.
        update: Box<UpdateInfo>,
    },
    /// A plugin exceeded its limits and was degraded or disabled.
    PluginHealthChanged {
        /// Which plugin.
        plugin_id: PluginId,
        /// Where it now sits, `snake_case`.
        health: String,
        /// A message key explaining it.
        explanation: String,
    },
    /// A plugin is asking the user to decide on its capabilities.
    PluginConsentRequested {
        /// Which plugin.
        plugin_id: PluginId,
        /// Its name, so the dialog does not need a lookup.
        title: String,
        /// What it is asking for.
        capabilities: Vec<String>,
        /// The digest the decision is recorded against.
        manifest_digest: String,
    },

    // ── Diagnostics ──
    /// One frame the transport sent or received, when the debug console asked for the wire.
    ///
    /// Only published while a sink is installed. The interface's floating console installs one for the life of the
    /// window; a daemon with no console pays nothing.
    DebugWire(Box<DebugWire>),
    /// A log line worth showing in the interface.
    ///
    /// Separate from `kernel://log`, which is the throttled bulk channel: this is the one or two lines a screen
    /// shows inline, and sending them through the bulk channel would make the screen's content depend on a
    /// throttle.
    LogLine {
        /// The level, `snake_case`.
        level: String,
        /// The already-redacted line.
        line: String,
    },
    /// Something the user should be told about, with nothing to decide.
    Notice {
        /// A message key.
        message: String,
        /// The values the sentence needs.
        params: serde_json::Value,
    },
}

impl KernelEvent {
    /// The `type` a caller branches on, as the wire spells it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::DeviceCardUpdated(_) => "deviceCardUpdated",
            Self::DeviceRemoved { .. } => "deviceRemoved",
            Self::ScanUpdated(_) => "scanUpdated",
            Self::PairingUpdated(_) => "pairingUpdated",
            Self::InputUpdated(_) => "inputUpdated",
            Self::IntentUpdated(_) => "intentUpdated",
            Self::IntentFinished { .. } => "intentFinished",
            Self::ConfigUpdated(_) => "configUpdated",
            Self::TransferUpdated(_) => "transferUpdated",
            Self::TransferFinished { .. } => "transferFinished",
            Self::PluginUpdated(_) => "pluginUpdated",
            Self::PluginInstallProgress { .. } => "pluginInstallProgress",
            Self::PluginUpdateAvailable { .. } => "pluginUpdateAvailable",
            Self::PluginHealthChanged { .. } => "pluginHealthChanged",
            Self::PluginConsentRequested { .. } => "pluginConsentRequested",
            Self::DebugWire(_) => "debugWire",
            Self::LogLine { .. } => "logLine",
            Self::Notice { .. } => "notice",
        }
    }

    /// Whether applying it twice would be wrong.
    ///
    /// A `remove` or a `finish` is idempotent: removing a device that is gone, or finishing a transfer that is
    /// finished, changes nothing. An `update` that carried a *count* would not be, and neither would a progress
    /// event — but those carry absolute values rather than deltas precisely so that a repeat is harmless. So this
    /// reports `false` for everything today, and exists so that a future event carrying a delta has to say so.
    #[must_use]
    pub const fn is_delta(&self) -> bool {
        false
    }
}

/// An event with its position in the sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelEventEnvelope {
    /// Monotonic, incremented by the kernel for every event it publishes.
    pub seq: u64,
    /// When it was published, in milliseconds since the epoch.
    ///
    /// For display and for a diagnostic report, not for ordering: the sequence is what orders, because two events
    /// published in the same millisecond are ordinary and a clock can move.
    pub at: i64,
    /// What changed.
    ///
    /// Flattened, so the interface reads `seq`, `at` and `type` from one object rather than nesting — which is what
    /// makes the tag reachable before the payload is parsed.
    #[serde(flatten)]
    pub event: KernelEvent,
}
