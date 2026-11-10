use super::*;

/// Where an intent came from.
///
/// # Why the source is kept rather than flattened into an action
///
/// Because it is what the *next* decision is made from: a share is matched by asking every plugin that declares a share
/// handler, a direct call names its plugin already, and a clipboard push is neither. Flattening these into "an action
/// and its arguments" would lose the fact that decides who gets asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IntentSource {
    /// The operating system's share sheet handed something over.
    Share {
        /// The shared item, as the inbound layer parsed it.
        item: synra_protocol::inbound::ShareItem,
        /// The application that shared it, when the platform said.
        source_app: Option<String>,
    },
    /// This device's own clipboard changed and the user asked for it to go somewhere.
    Clipboard {
        /// Which device it is meant for, or `None` to ask.
        target: Option<DeviceId>,
    },
    /// A plugin's own window asked for something.
    PluginUi {
        /// Which plugin.
        plugin_id: PluginId,
        /// Which action.
        action: String,
        /// Its arguments.
        params: serde_json::Value,
    },
    /// Somebody named the plugin and the action directly: a CLI, a test, a deep link.
    Direct {
        /// Which plugin.
        plugin_id: PluginId,
        /// Which action.
        action: String,
        /// Its arguments.
        params: serde_json::Value,
        /// Where it should run.
        target: DeviceId,
    },
}

impl IntentSource {
    /// A short name, for a log line and a metric label.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Share { .. } => "share",
            Self::Clipboard { .. } => "clipboard",
            Self::PluginUi { .. } => "plugin-ui",
            Self::Direct { .. } => "direct",
        }
    }

    /// The plugin already named by the source, when there is one.
    ///
    /// A [`IntentSource::Direct`] or [`IntentSource::PluginUi`] names its plugin, so nothing has to be matched: the
    /// candidate list has one entry and the matching phase has no questions to ask. Answering `None` here is what makes
    /// a share go through matching.
    #[must_use]
    pub const fn named_plugin(&self) -> Option<&PluginId> {
        match self {
            Self::PluginUi { plugin_id, .. } | Self::Direct { plugin_id, .. } => Some(plugin_id),
            Self::Share { .. } | Self::Clipboard { .. } => None,
        }
    }

    /// The device the source already chose, when it did.
    #[must_use]
    pub const fn named_target(&self) -> Option<DeviceId> {
        match self {
            Self::Clipboard { target } => *target,
            Self::Direct { target, .. } => Some(*target),
            Self::Share { .. } | Self::PluginUi { .. } => None,
        }
    }

    /// The candidate this source implies without asking anyone, when it implies one.
    #[must_use]
    pub fn implied_action(&self) -> Option<PlannedAction> {
        // Two arms rather than one with an `|`: `Direct` carries a `target` that `PluginUi` does not, and a pattern
        // that names only the shared fields is the one a field added to either variant would silently stop binding.
        let (plugin_id, action, params) = match self {
            Self::PluginUi {
                plugin_id,
                action,
                params,
            } => (plugin_id, action, params),
            Self::Direct {
                plugin_id,
                action,
                params,
                ..
            } => (plugin_id, action, params),
            Self::Share { .. } | Self::Clipboard { .. } => return None,
        };
        Some(PlannedAction {
            plugin_id: plugin_id.clone(),
            action: action.clone(),
            args: params.clone(),
        })
    }
}
