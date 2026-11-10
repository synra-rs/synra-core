use crate::ids::PluginId;

/// A host event, with its payload parsed into the shape the host guarantees.
///
/// Strongly typed, unlike a plugin event's payload. The host defines these shapes, so it can; only a
/// plugin's own event needs to stay a `RawValue` because the kernel genuinely does not know what is
/// in it. A plugin using a built-in therefore never hand-writes a field name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuiltinEvent {
    /// Paired devices came online, went offline, or changed. A full snapshot.
    DeviceChanged {
        /// Every paired device, as of now.
        devices: Vec<DeviceSnapshot>,
    },
    /// One device went offline.
    DeviceOffline {
        /// Which device.
        device: crate::ids::DeviceId,
        /// When it was last heard from, in milliseconds since the epoch.
        last_seen_at_ms: i64,
    },
    /// One device's display name changed.
    DeviceRenamed {
        /// Which device.
        device: crate::ids::DeviceId,
        /// Its new name.
        display_name: String,
    },
    /// Shared content arrived that no plugin claimed.
    ShareReceived {
        /// What was shared.
        item: ShareItem,
    },
    /// An action this device asked for finished.
    IntentCompleted(crate::session::IntentOutcome),
    /// An action this device asked for failed.
    IntentFailed(crate::session::IntentOutcome),
    /// A transfer finished and its digest was checked.
    TransferCompleted {
        /// Which transfer.
        transfer: crate::ids::TransferId,
        /// Where the bytes landed, as an absolute path the plugin may open.
        ///
        /// Delivered by the kernel so the plugin never has to reconstruct a path from ids, which is
        /// where a traversal bug would come from.
        path: String,
        /// Size in bytes.
        byte_length: u64,
    },
    /// A transfer failed or was aborted.
    TransferFailed {
        /// Which transfer.
        transfer: crate::ids::TransferId,
        /// Why.
        reason: crate::session::TransferAbortReason,
    },
    /// Transfer progress. Coalescable: see the module docs.
    TransferProgress(crate::session::TransferProgress),
    /// Clipboard content arrived from a peer.
    ClipboardReceived {
        /// The text, when the clipboard held text.
        text: Option<String>,
        /// The MIME type the peer declared.
        mime: String,
        /// Which device sent it.
        from: crate::ids::DeviceId,
    },
    /// A plugin was installed on this device.
    PluginInstalled {
        /// Which plugin.
        plugin: PluginId,
        /// Its version.
        version: String,
    },
    /// A plugin was updated on this device.
    PluginUpdated {
        /// Which plugin.
        plugin: PluginId,
        /// The version it was.
        from: String,
        /// The version it became.
        to: String,
    },
    /// A plugin was uninstalled from this device.
    PluginUninstalled {
        /// Which plugin.
        plugin: PluginId,
    },
    /// A plugin's granted capabilities changed.
    PluginCapabilityChanged {
        /// Which plugin.
        plugin: PluginId,
        /// The capabilities it now holds, as DSL strings.
        capabilities: Vec<String>,
    },
    /// The host came to the foreground.
    HostForeground,
    /// The host is going to the background and will be suspended shortly.
    HostBackground,
    /// A network interface changed.
    NetworkChanged {
        /// What happened.
        kind: NetworkChangeKind,
    },
}

/// How the network changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChangeKind {
    /// An interface came up.
    Up,
    /// An interface went down.
    Down,
    /// An interface's address changed.
    AddressChanged,
}

/// One device, as reported in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    /// The device's id.
    pub device_id: crate::ids::DeviceId,
    /// The name to show a human.
    pub display_name: String,
    /// Which platform it runs.
    pub platform: crate::session::PlatformKind,
    /// Whether it is reachable now.
    pub online: bool,
    /// When it was last heard from.
    pub last_seen_at_ms: i64,
}

/// A shared item, as it arrived from a peer.
///
/// # Why this is serialisable
///
/// Because a plugin is handed this as JSON: `can-handle` receives the item as text, and the shape it is parsed from has
/// to be the shape the rest of the system holds. A second, hand-written serialisation for the plugin boundary would be a
/// second definition of what a share is, and the two would drift — a plugin would be asked about a different object from
/// the one the kernel routed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareItem {
    /// Which device shared it.
    pub from: crate::ids::DeviceId,
    /// The MIME type the peer declared.
    pub mime: String,
    /// Text content, when it is text.
    pub text: Option<String>,
    /// Transfers carrying the content, when it is not text.
    pub transfers: Vec<crate::ids::TransferId>,
    /// An opaque grouping id, so a plugin can tie related shares together.
    pub context_id: Option<String>,
}
