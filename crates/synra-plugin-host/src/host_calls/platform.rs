/// The seven actions `platform:*` covers, as the host names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlatformAction {
    /// Open a URL in the user's browser.
    OpenUrl,
    /// Open a file or directory with the system's handler.
    OpenPath,
    /// Show a file in the system's file manager.
    RevealPath,
    /// Synthesize a keystroke.
    SimulateKeys,
    /// Show a notification.
    Notify,
    /// Read the clipboard.
    ReadClipboard,
    /// Write the clipboard.
    WriteClipboard,
}

impl PlatformAction {
    /// Every action, in the order the contract lists them.
    pub const ALL: &'static [Self] = &[
        Self::OpenUrl,
        Self::OpenPath,
        Self::RevealPath,
        Self::SimulateKeys,
        Self::Notify,
        Self::ReadClipboard,
        Self::WriteClipboard,
    ];

    /// The name the contract uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenUrl => "openUrl",
            Self::OpenPath => "openPath",
            Self::RevealPath => "revealPath",
            Self::SimulateKeys => "simulateKeys",
            Self::Notify => "notify",
            Self::ReadClipboard => "readClipboard",
            Self::WriteClipboard => "writeClipboard",
        }
    }

    /// The capability it needs, which is one per action rather than one `platform:*`.
    ///
    /// # Why this is a method and not a table
    ///
    /// Because the contract's own claim is that a plugin which notifies has no business simulating keystrokes, and one
    /// capability for both would make the permission dialog ask for both. A table would let a new action be added with
    /// the wrong gate; here the mapping is the thing being written.
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::OpenUrl => "platform:open-url",
            Self::OpenPath => "platform:open-path",
            Self::RevealPath => "platform:reveal-path",
            Self::SimulateKeys => "platform:simulate-keys",
            Self::Notify => "platform:notify",
            Self::ReadClipboard => "platform:read-clipboard",
            Self::WriteClipboard => "platform:write-clipboard",
        }
    }

    /// The action with this name, when it is one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|action| action.as_str() == name)
    }
}
