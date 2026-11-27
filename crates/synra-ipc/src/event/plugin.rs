//! The projected page stream, with no management event or private device fields on its wire.

use serde::{Deserialize, Serialize};
use synra_protocol::DeviceId;

use crate::{DeviceCard, PluginTransferStatus};

/// Platform labels available to plugin device pickers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PluginDevicePlatform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
    /// Linux.
    Linux,
    /// Android.
    Android,
    /// iOS.
    Ios,
    /// Discovery knows the device is a desktop, but does not know its operating system.
    Desktop,
    /// A headless process.
    Headless,
}

/// A stored device platform falls outside the public device contract.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized device platform {0:?}")]
pub struct UnknownDevicePlatform(String);

impl TryFrom<&str> for PluginDevicePlatform {
    type Error = UnknownDevicePlatform;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "windows" => Ok(Self::Windows),
            "macos" => Ok(Self::Macos),
            "linux" => Ok(Self::Linux),
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            "desktop" => Ok(Self::Desktop),
            "headless" => Ok(Self::Headless),
            _ => Err(UnknownDevicePlatform(value.to_owned())),
        }
    }
}

/// One paired, unblocked device as a plugin page may see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginDeviceTarget {
    /// Stable device identifier.
    pub device_id: DeviceId,
    /// Name to display to the plugin user.
    pub display_name: String,
    /// Public platform label.
    pub platform: PluginDevicePlatform,
    /// Current availability. Offline devices remain part of the collection.
    pub online: bool,
}

impl PluginDeviceTarget {
    /// Project a management card through the visibility rule shared by list and event delivery.
    ///
    /// # Errors
    /// Returns an error when a visible device has an unrecognized platform label.
    pub fn from_card(card: &DeviceCard) -> Result<Option<Self>, UnknownDevicePlatform> {
        if !card.paired || card.blocked {
            return Ok(None);
        }
        Ok(Some(Self {
            device_id: card.device_id,
            display_name: card.display_name.clone(),
            platform: PluginDevicePlatform::try_from(card.platform.as_str())?,
            online: card.online,
        }))
    }
}

/// The complete visible device collection after a device change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginDevicesChanged {
    /// Paired, unblocked devices, including offline entries.
    pub devices: Vec<PluginDeviceTarget>,
}

/// A public effect that the host may deliver after checking page authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "name", content = "payload")]
#[non_exhaustive]
pub enum PluginEvent {
    /// A visible device collection changed.
    #[serde(rename = "device.changed")]
    DevicesChanged(PluginDevicesChanged),
    /// The current or terminal state of a transfer owned by the receiving plugin.
    #[serde(rename = "transfer.progress")]
    TransferProgress(PluginTransferStatus),
}

impl PluginEvent {
    /// Public topic for the paired-device snapshot.
    pub const DEVICES_CHANGED: &'static str = "device.changed";
    /// Public topic for transfer status snapshots.
    pub const TRANSFER_PROGRESS: &'static str = "transfer.progress";

    /// The event name used to match subscriptions.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DevicesChanged(_) => Self::DEVICES_CHANGED,
            Self::TransferProgress(_) => Self::TRANSFER_PROGRESS,
        }
    }
}

/// One delivery on a particular page stream. Sequences are assigned after projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginEventEnvelope {
    /// Monotonic sequence in this page stream, independent of the management bus.
    pub seq: u64,
    /// Milliseconds since the epoch when projected by the host.
    pub at: i64,
    /// The named public event.
    #[serde(flatten)]
    pub event: PluginEvent,
}

/// A page poll result. A lost host delivery asks the page to recover its snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PluginEventPoll {
    /// One sequenced event.
    Event(PluginEventEnvelope),
    /// The host cannot guarantee a continuous history for this page.
    Reconcile {
        /// Set when the page must call `event.resync` before polling again.
        resync: bool,
    },
}

/// Authoritative snapshots and the next poll's sequence watermark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginEventRecovery {
    /// Highest sequence retired by the recovery.
    pub seq: u64,
    /// Current snapshots matching the page's authorized subscriptions.
    pub events: Vec<PluginEvent>,
}

#[cfg(test)]
mod tests;
