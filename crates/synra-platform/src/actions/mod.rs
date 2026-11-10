//! What a host can be asked to do, and how far its permission reaches.
//!
//! # Why the limits live here
//!
//! Because a limit is part of what an action *is*: an address is at most `MAX_URL_LEN`, a notification at most
//! `MAX_NOTIFICATION_LEN`. A reader of these types should not have to find the validator to learn that.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Which host action is being considered.
///
/// Each variant names one operating-system effect, and none is a superset of another: a policy that allowed
/// opening a URL must not thereby allow opening a file, because a file can be executable and a URL cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PlatformAction {
    /// Open a URL in the user's browser.
    OpenUrl,
    /// Open a path with the platform's default application.
    OpenPath,
    /// Show a path in the user's file manager.
    RevealPath,
    /// Type a key chord into whatever has focus.
    SimulateKeys,
    /// Read the clipboard.
    ReadClipboard,
    /// Replace the clipboard's contents.
    WriteClipboard,
    /// Show a notification.
    Notify,
}

impl PlatformAction {
    /// The capability that gates this action.
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::OpenUrl => "platform:open-url",
            Self::OpenPath => "platform:open-path",
            Self::RevealPath => "platform:reveal-path",
            Self::SimulateKeys => "platform:simulate-keys",
            Self::ReadClipboard => "platform:read-clipboard",
            Self::WriteClipboard => "platform:write-clipboard",
            Self::Notify => "platform:notify",
        }
    }

    /// Whether the action has an effect the user can see while it happens.
    ///
    /// The three that do: a browser window, a file manager, a notification. The others are silent, which is why
    /// they need something else — see [`Self::needs_visible_indicator`].
    #[must_use]
    pub const fn is_user_visible(self) -> bool {
        matches!(
            self,
            Self::OpenUrl | Self::OpenPath | Self::RevealPath | Self::Notify
        )
    }

    /// Whether the action is silent and therefore needs an indicator of its own.
    ///
    /// Simulating keys and reading the clipboard both happen with nothing on screen to say so. The design
    /// document calls for a tray indicator for the clipboard, and for simulate-keys to be restricted to a
    /// foreground interaction — a plugin that types while the user is elsewhere is acting without them.
    #[must_use]
    pub const fn needs_visible_indicator(self) -> bool {
        matches!(self, Self::SimulateKeys | Self::ReadClipboard)
    }

    /// Whether granting this one is the user's decision alone, and off by default.
    ///
    /// Only simulating keys. It is the one action that lets a plugin drive *other* applications, and the design
    /// document is explicit that it must not be granted by default and must be shown in red.
    #[must_use]
    pub const fn is_off_by_default(self) -> bool {
        matches!(self, Self::SimulateKeys)
    }

    /// A sentence naming the risk, for the consent screen.
    #[must_use]
    pub const fn risk(self) -> &'static str {
        match self {
            Self::OpenUrl => "can open any web page in your browser",
            Self::OpenPath => "can open files, and a file can be a program",
            Self::RevealPath => "can show file locations, which tells it what exists on your disk",
            Self::SimulateKeys => "can type into your other applications, as if you were typing",
            Self::ReadClipboard => "can read whatever is on your clipboard, including passwords",
            Self::WriteClipboard => "can replace what is on your clipboard",
            Self::Notify => "can show notifications",
        }
    }
}

impl fmt::Display for PlatformAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.capability())
    }
}

/// File extensions that may not be opened.
///
/// Opened with the default application, an executable runs. The list is by extension rather than by inspecting
/// the file, because an extension check cannot be raced: the file can be replaced between an inspection and the
/// open, and the check would then have approved something else.
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    // Windows
    "exe", "com", "bat", "cmd", "msi", "msp", "scr", "pif", "cpl", "hta", "jar", "ps1", "psm1",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "lnk", "inf", "reg", "dll", "sys", "ocx",
    // Unix and macOS
    "sh", "bash", "zsh", "fish", "run", "bin", "app", "command", "workflow", "scpt", "desktop",
    "so", "dylib", // Anything that installs or configures
    "pkg", "dmg", "deb", "rpm", "appimage", "apk",
];

/// The longest a URL may be.
pub const MAX_URL_LEN: usize = 8 * 1024;

/// The longest a notification's title or body may be.
pub const MAX_NOTIFICATION_LEN: usize = 512;

/// The longest a key chord may be.
pub const MAX_CHORD_LEN: usize = 128;

/// The longest clipboard text a plugin may read or write, measured in UTF-8 bytes.
///
/// Bounded because a clipboard can hold megabytes — an image, a whole document — and a plugin that asked for it
/// would be handed the user's data in bulk. A plugin wanting a large object uses `file.transfer`, which the user
/// can see and cancel.
pub const MAX_CLIPBOARD_BYTES: usize = 256 * 1024;

mod policy;

pub use policy::Policies;
