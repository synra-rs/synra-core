use synra_protocol::ids::DeviceId;
use synra_store::records::{DeviceRow, PluginRow};

use super::model::NodeRole;
use crate::identity::Identity;

/// What an interface draws.
///
/// # Why this is assembled from the same readers the events are
///
/// Because the two have to agree. An interface asks for this once when a screen opens and then applies events to it;
/// if the snapshot and the events came from different places, a device could appear in one and not the other, and the
/// symptom would be a list that changes when the window is resized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSnapshot {
    /// This device.
    pub identity: Identity,
    /// Every device this device is paired with.
    pub devices: Vec<DeviceRow>,
    /// Every plugin the store knows about.
    pub plugins: Vec<PluginRow>,
    /// How many settings the user has overridden.
    pub config_overrides: usize,
    /// Which role this kernel plays.
    pub role: NodeRole,
    /// Whether the network has been started.
    pub started: bool,
}

impl KernelSnapshot {
    /// The paired devices that are usable, which is what a send menu offers.
    #[must_use]
    pub fn sendable(&self) -> Vec<&DeviceRow> {
        self.devices
            .iter()
            .filter(|device| device.is_usable())
            .collect()
    }

    /// A plugin by identifier.
    #[must_use]
    pub fn plugin(&self, plugin_id: &str) -> Option<&PluginRow> {
        self.plugins
            .iter()
            .find(|plugin| plugin.plugin_id == plugin_id)
    }

    /// A device by identifier.
    #[must_use]
    pub fn device(&self, device_id: DeviceId) -> Option<&DeviceRow> {
        let wanted = device_id.to_string();
        self.devices
            .iter()
            .find(|device| device.device_id == wanted)
    }
}
