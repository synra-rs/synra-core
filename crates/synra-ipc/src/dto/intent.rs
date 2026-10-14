//! What the user is trying to do, and the decision they made about it.

use serde::{Deserialize, Serialize};

use synra_protocol::{DeviceId, IntentId, PluginId};

// ─────────────────────────────────────────────────────────────────────────────
// Intents
// ─────────────────────────────────────────────────────────────────────────────

/// What the user is trying to do, from the interface's point of view.
///
/// Internally tagged so the interface can switch on `kind`, and each variant carries only what that kind needs —
/// a share has text and a file has a path, and a single struct with both optional would let the interface send a
/// share with neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
#[non_exhaustive]
pub enum IntentSourceDto {
    /// The user shared text.
    Share {
        /// The text.
        text: String,
        /// An optional title the sharing application supplied.
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    /// The user shared files.
    ShareFiles {
        /// The paths, as the interface received them.
        paths: Vec<String>,
    },
    /// The user asked to send the clipboard.
    Clipboard,
    /// The user invoked a plugin's action from its own page.
    PluginAction {
        /// The plugin.
        plugin_id: PluginId,
        /// The action.
        action: String,
        /// Its arguments, as JSON.
    args: serde_json::Value,
    },
}

impl IntentSourceDto {
    /// The `kind` a caller branches on, as the wire spells it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Share { .. } => "share",
            Self::ShareFiles { .. } => "shareFiles",
            Self::Clipboard => "clipboard",
            Self::PluginAction { .. } => "pluginAction",
        }
    }

    /// Whether this source carries content the user would not want in a log.
    ///
    /// The kernel records the *kind* of an intent and never its content, and the interface's diagnostics screen
    /// uses this to decide whether to say so. A share's title is user content; a plugin action's arguments are
    /// whatever the plugin decided.
    #[must_use]
    pub const fn carries_user_content(&self) -> bool {
        true
    }
}

/// Where an intent has got to.
///
/// Not `Eq`, because it may carry an [`crate::IpcError`] whose parameters are a JSON value — and a JSON value
/// containing a float has no total equality. `PartialEq` is what the interface's tests need.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentSnapshot {
    /// The intent.
    pub intent_id: IntentId,
    /// What stage it is at. `snake_case`, matching the kernel's own states.
    pub state: String,
    /// The plugin the kernel chose, if it has chosen one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<PluginId>,
    /// The devices that could run it, for a chooser.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<IntentCandidate>,
    /// What the user is being asked, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<IntentPrompt>,
    /// Why it failed, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::IpcError>,
    /// When it started, in milliseconds since the epoch.
    pub started_at_ms: i64,
}

/// One way an intent could be handled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentCandidate {
    /// The plugin that would handle it.
    pub plugin_id: PluginId,
    /// The plugin's name, for the chooser.
    pub title: String,
    /// Which device would run it.
    pub device_id: DeviceId,
    /// Whether that device is reachable now.
    pub online: bool,
}

/// What the user is being asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentPrompt {
    /// The message key for the question.
    pub message: String,
    /// The values the question needs.
    pub params: serde_json::Value,
    /// What the user may choose.
    pub options: Vec<String>,
}

/// What the user decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "decision")]
#[non_exhaustive]
pub enum IntentDecisionDto {
    /// Let it proceed, on the given device.
    Accept {
        /// The device to run it on.
        device_id: DeviceId,
    },
    /// Let it proceed on whichever device the kernel chose.
    AcceptDefault,
    /// Refuse it.
    Decline {
        /// A reason the other side is told, if the user gave one.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl IntentDecisionDto {
    /// The `decision` a caller branches on.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Accept { .. } => "accept",
            Self::AcceptDefault => "acceptDefault",
            Self::Decline { .. } => "decline",
        }
    }

    /// Whether it lets the intent proceed.
    #[must_use]
    pub const fn is_accepting(&self) -> bool {
        matches!(self, Self::Accept { .. } | Self::AcceptDefault)
    }
}
