//! The projected page stream, with no management event or private device fields on its wire.

use serde::{Deserialize, Serialize};
use synra_protocol::{DeviceId, event::EventName};

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
    /// A custom event with its validated fully qualified topic.
    #[serde(untagged)]
    Custom(PluginCustomEvent),
}

impl PluginEvent {
    /// Public topic for the paired-device snapshot.
    pub const DEVICES_CHANGED: &'static str = "device.changed";
    /// Public topic for transfer status snapshots.
    pub const TRANSFER_PROGRESS: &'static str = "transfer.progress";

    /// The event name used to match subscriptions.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::DevicesChanged(_) => Self::DEVICES_CHANGED,
            Self::TransferProgress(_) => Self::TRANSFER_PROGRESS,
            Self::Custom(event) => event.name.as_str(),
        }
    }
}

/// The public name and JSON object from a custom plugin event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCustomEvent {
    #[serde(deserialize_with = "custom_event_name")]
    name: EventName,
    /// The bounded application payload checked by the event service.
    pub payload: serde_json::Map<String, serde_json::Value>,
}

impl PluginCustomEvent {
    /// Construct a page event from a validated plugin topic and its object payload.
    #[must_use]
    pub fn new(
        name: EventName,
        payload: serde_json::Map<String, serde_json::Value>,
    ) -> Option<Self> {
        name.is_plugin().then_some(Self { name, payload })
    }
}

fn custom_event_name<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<EventName, D::Error> {
    let name = EventName::deserialize(decoder)?;
    if name.is_plugin() {
        Ok(name)
    } else {
        Err(serde::de::Error::custom(
            "expected a custom plugin event name",
        ))
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginEventRecovery {
    /// Highest sequence retired by the recovery.
    pub seq: u64,
    /// Current snapshots matching the page's authorized subscriptions.
    pub events: Vec<PluginEvent>,
    /// Logical subscriptions with custom occurrences beyond the page's acknowledged sequence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreplayed_subscription_ids: Vec<u32>,
}

#[cfg(test)]
mod tests;
