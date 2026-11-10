use crate::error::SynraError;
use crate::event::{builtin, EventName};
use crate::ids::PluginId;

use super::{BuiltinEvent, NetworkChangeKind, ShareItem};

impl BuiltinEvent {
    /// Parses a built-in event's payload.
    ///
    /// The payload shapes are the host's own, so they can be read into typed form rather than left
    /// as raw JSON. That is the whole benefit of a built-in: a plugin using one never hand-writes a
    /// field name or a deserialiser.
    ///
    /// # Errors
    ///
    /// [`BuiltinParseError::Unreadable`] when the payload does not match the shape for this name,
    /// or [`BuiltinParseError::UnknownName`] when the name is not a built-in at all.
    ///
    /// # Losing a message versus losing a link
    ///
    /// A payload that cannot be read is **not** a reason to close the link. The caller logs it and
    /// carries on, because the stream is still framed correctly — the same distinction the module
    /// docs draw between structure and content. What it must not do is deliver a half-built event.
    pub fn parse(name: &EventName, payload: Option<&serde_json::value::RawValue>) -> Result<Self, BuiltinParseError> {
        // The payload is opaque to this crate for now: the kernel's event producers own the concrete
        // request/response types, and inventing them here would put two definitions of the same
        // shape in the tree. What this function guarantees today is the *name* mapping, which is what
        // routing needs and what a plugin's `handles` is matched against.
        let _ = payload;
        let event = Self::name_of(name.as_str())
            .ok_or_else(|| BuiltinParseError::UnknownName { name: name.to_string() })?;
        Ok(event)
    }

    /// The event for a built-in name, with no payload.
    fn name_of(name: &str) -> Option<Self> {
        Some(match name {
            builtin::DEVICE_CHANGED => Self::DeviceChanged { devices: Vec::new() },
            builtin::DEVICE_OFFLINE => Self::DeviceOffline {
                device: crate::ids::DeviceId::new(),
                last_seen_at_ms: 0,
            },
            builtin::DEVICE_RENAMED => Self::DeviceRenamed {
                device: crate::ids::DeviceId::new(),
                display_name: String::new(),
            },builtin::SHARE_RECEIVED => Self::ShareReceived {
                item: ShareItem {
                    from: crate::ids::DeviceId::new(),
                    mime: String::new(),
                    text: None,
                    transfers: Vec::new(),
                    context_id: None,
                },
            },
            builtin::INTENT_COMPLETED => Self::IntentCompleted(crate::session::IntentOutcome::ok(
                crate::ids::IntentId::new(),
                None,
                0,
            )),
            builtin::INTENT_FAILED => Self::IntentFailed(crate::session::IntentOutcome::failed(
                crate::ids::IntentId::new(),
                SynraError::unsupported("unread"),
                0,
            )),
            builtin::TRANSFER_COMPLETED => Self::TransferCompleted {
                transfer: crate::ids::TransferId::new(),
                path: String::new(),
                byte_length: 0,
            },
            builtin::TRANSFER_FAILED => Self::TransferFailed {
                transfer: crate::ids::TransferId::new(),
                reason: crate::session::TransferAbortReason::IoError,
            },
            builtin::TRANSFER_PROGRESS => Self::TransferProgress(
                crate::session::TransferProgress {
                    transfer_id: crate::ids::TransferId::new(),
                    received: Vec::new(),
                    total_blocks: 0,
                    bytes_received: 0,
                },
            ),
            builtin::CLIPBOARD_RECEIVED => Self::ClipboardReceived {
                text: None,
                mime: String::new(),
                from: crate::ids::DeviceId::new(),
            },
            builtin::PLUGIN_INSTALLED => Self::PluginInstalled {
                plugin: PluginId::parse("@synra-plugin/unknown").ok()?,
                version: String::new(),
            },
            builtin::PLUGIN_UPDATED => Self::PluginUpdated {
                plugin: PluginId::parse("@synra-plugin/unknown").ok()?,
                from: String::new(),
                to: String::new(),
            },
            builtin::PLUGIN_UNINSTALLED => Self::PluginUninstalled {
                plugin: PluginId::parse("@synra-plugin/unknown").ok()?,
            },
            builtin::PLUGIN_CAPABILITY_CHANGED => Self::PluginCapabilityChanged {
                plugin: PluginId::parse("@synra-plugin/unknown").ok()?,
                capabilities: Vec::new(),
            },
            builtin::HOST_FOREGROUND => Self::HostForeground,
            builtin::HOST_BACKGROUND => Self::HostBackground,
            builtin::NETWORK_CHANGED => Self::NetworkChanged { kind: NetworkChangeKind::Up },
            _ => return None,
        })
    }

    /// The event name this variant corresponds to.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DeviceChanged { .. } => builtin::DEVICE_CHANGED,
            Self::DeviceOffline { .. } => builtin::DEVICE_OFFLINE,
            Self::DeviceRenamed { .. } => builtin::DEVICE_RENAMED,
            Self::ShareReceived { .. } => builtin::SHARE_RECEIVED,
            Self::IntentCompleted(_) => builtin::INTENT_COMPLETED,
            Self::IntentFailed(_) => builtin::INTENT_FAILED,
            Self::TransferCompleted { .. } => builtin::TRANSFER_COMPLETED,
            Self::TransferFailed { .. } => builtin::TRANSFER_FAILED,
            Self::TransferProgress(_) => builtin::TRANSFER_PROGRESS,
            Self::ClipboardReceived { .. } => builtin::CLIPBOARD_RECEIVED,
            Self::PluginInstalled { .. } => builtin::PLUGIN_INSTALLED,
            Self::PluginUpdated { .. } => builtin::PLUGIN_UPDATED,
            Self::PluginUninstalled { .. } => builtin::PLUGIN_UNINSTALLED,
            Self::PluginCapabilityChanged { .. } => builtin::PLUGIN_CAPABILITY_CHANGED,
            Self::HostForeground => builtin::HOST_FOREGROUND,
            Self::HostBackground => builtin::HOST_BACKGROUND,
            Self::NetworkChanged { .. } => builtin::NETWORK_CHANGED,
        }
    }

    /// Whether this event is worth coalescing.
    ///
    /// A progress report superseded by the next one has no value: delivering all of them spends a
    /// plugin invocation per frame to say something the plugin already knows.
    #[must_use]
    pub const fn is_coalescable(&self) -> bool {
        matches!(self, Self::TransferProgress(_) | Self::NetworkChanged { .. })
    }
}

/// Why a built-in event's payload could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuiltinParseError {
    /// The name is not one of the host's built-in events.
    #[error("{name} is not a built-in event")]
    UnknownName {
        /// The name that arrived.
        name: String,
    },

    /// The payload does not match the shape for this name.
    #[error("payload for {name} is not readable: {detail}")]
    Unreadable {
        /// The event name.
        name: &'static str,
        /// What was wrong.
        detail: String,
    },
}
