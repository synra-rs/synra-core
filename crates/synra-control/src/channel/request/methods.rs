//! Request helper methods.

use super::Request;

impl Request {
    /// The name a log line and a test use.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Status => "status",
            Self::Devices { .. } => "devices",
            Self::SendText { .. } => "sendText",
            Self::SendFile { .. } => "sendFile",
            Self::Plugins => "plugins",
            Self::PluginPublishers => "pluginPublishers",
            Self::PluginPublisherDecide { .. } => "pluginPublisherDecide",
            Self::PluginRegistry { .. } => "pluginRegistry",
            Self::PluginUpdatePolicy { .. } => "pluginUpdatePolicy",
            Self::PluginCheckUpdates { .. } => "pluginCheckUpdates",
            Self::PluginUpdate { .. } => "pluginUpdate",
            Self::IntentDispatch { .. } => "intentDispatch",
            Self::CatalogSearch { .. } => "catalogSearch",
            Self::PluginSetEnabled { .. } => "pluginSetEnabled",
            Self::PluginInstall { .. } => "pluginInstall",
            Self::PluginInstallPackage { .. } => "pluginInstallPackage",
            Self::PluginConsent { .. } => "pluginConsent",
            Self::PluginRemove { .. } => "pluginRemove",
            Self::IntentCancel { .. } => "intentCancel",
            Self::IntentDecide { .. } => "intentDecide",
            Self::IntentSnapshot { .. } => "intentSnapshot",
            Self::Logs { .. } => "logs",
        }
    }

    /// Whether this request is the handshake.
    ///
    /// A kernel answers `Hello` even when the version does not match — that answer is *how* the client learns the
    /// version — and refuses every other request until the handshake has happened.
    #[must_use]
    pub const fn is_handshake(&self) -> bool {
        matches!(self, Self::Hello { .. })
    }
}


