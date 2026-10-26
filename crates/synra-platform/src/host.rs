//! What a host can do, and the host that does nothing.
//!
//! # Why `HeadlessPlatform` is in the library and not in a test
//!
//! Because two real binaries need it — the CLI and the daemon — and a fake that only tests use is a fake that drifts
//! from the ones that ship.

use std::path::Path;

use super::actions::{PlatformAction, Policies};
use super::error::PlatformError;
use super::guard::{
    PathUse, check_clipboard_text, check_key_chord, check_notification, check_path, check_url,
};

/// What a host can do.
///
/// Implemented by the application layer, over Tauri. Every method answers [`PlatformError::Unsupported`] where
/// the platform has no such facility — a headless build has no clipboard and no browser — because a caller's
/// response to "this host never had that" differs from its response to "the system refused".
pub trait Platform: Send + Sync {
    /// The name of the platform, for a diagnostic report.
    fn name(&self) -> &'static str;

    /// The policies in force.
    fn policies(&self) -> &Policies;

    /// Opens a URL in the user's browser.
    ///
    /// # Errors
    ///
    /// [`PlatformError::BadUrl`] if the address is refused, or [`PlatformError::Unavailable`] if the system
    /// would not open it.
    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        check_url(url, self.policies())
    }

    /// Opens a path with the default application.
    ///
    /// # Errors
    ///
    /// [`PlatformError::BadPath`] if the path is refused.
    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        check_path(path, PathUse::Open, self.policies(), None)
    }

    /// Shows a path in the file manager.
    ///
    /// # Errors
    ///
    /// [`PlatformError::BadPath`] if the path is refused.
    fn reveal_path(
        &self,
        path: &Path,
        sandbox_root: Option<&Path>,
    ) -> Result<(), PlatformError> {
        check_path(path, PathUse::Reveal, self.policies(), sandbox_root)
    }

    /// Types a key chord into whatever has focus.
    ///
    /// # Errors
    ///
    /// [`PlatformError::SimulateKeysNotGranted`], [`PlatformError::NoRecentInteraction`] or
    /// [`PlatformError::Unavailable`].
    fn simulate_keys(&self, chord: &str) -> Result<(), PlatformError> {
        let _ = chord;
        Err(PlatformError::Unsupported("simulate keys"))
    }

    /// Reads the clipboard.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Unsupported`] where there is no clipboard.
    fn read_clipboard(&self) -> Result<Option<String>, PlatformError> {
        Err(PlatformError::Unsupported("read the clipboard"))
    }

    /// Replaces the clipboard.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Unsupported`] where there is no clipboard.
    fn write_clipboard(&self, text: &str) -> Result<(), PlatformError> {
        let _ = text;
        Err(PlatformError::Unsupported("write to the clipboard"))
    }

    /// Shows a notification.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Unsupported`] where there is no notification facility.
    fn notify(&self, title: &str, body: &str) -> Result<(), PlatformError> {
        let _ = (title, body);
        Err(PlatformError::Unsupported("show a notification"))
    }

    /// Which of the actions this host can perform at all.
    ///
    /// Reported to the interface so a plugin's settings page does not offer a permission the host cannot honour.
    /// A user who grants "read the clipboard" on a host with no clipboard has agreed to nothing.
    fn supported_actions(&self) -> Vec<PlatformAction> {
        vec![PlatformAction::OpenUrl]
    }
}

/// A host that performs nothing.
///
/// For the CLI, for a daemon, and for tests. Every action reports [`PlatformError::Unsupported`] rather than
/// pretending to succeed, so a caller that forgot to provide a real implementation finds out immediately instead
/// of at the point a user expected a browser window.
#[derive(Debug, Clone)]
pub struct HeadlessPlatform {
    policies: Policies,
}

impl Default for HeadlessPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl HeadlessPlatform {
    /// A headless host with the default policies.
    #[must_use]
    pub fn new() -> Self {
        Self { policies: Policies::new() }
    }

    /// A headless host with the given policies.
    #[must_use]
    pub const fn with_policies(policies: Policies) -> Self {
        Self { policies }
    }
}

impl Platform for HeadlessPlatform {
    fn name(&self) -> &'static str {
        "headless"
    }

    fn policies(&self) -> &Policies {
        &self.policies
    }

    /// Checks the URL and then refuses, so a caller still learns about a bad address rather than about the host.
    ///
    /// The order matters: a plugin that supplied `javascript:` should be told its address is refused, not that
    /// this host has no browser. The first is a mistake the author can fix and the second is a fact about the
    /// installation.
    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        check_url(url, &self.policies)?;
        Err(PlatformError::Unsupported("open a web page"))
    }

    /// Checks the path and then refuses.
    ///
    /// Every method here overrides the trait's default, which only runs the policy checks. A default that returns
    /// `Ok(())` after checking is a host that reports success for an action it never performed — and a caller would
    /// then tell the user a browser window was opened.
    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        check_path(path, PathUse::Open, &self.policies, None)?;
        Err(PlatformError::Unsupported("open a file"))
    }

    fn reveal_path(&self, path: &Path, sandbox_root: Option<&Path>) -> Result<(), PlatformError> {
        check_path(path, PathUse::Reveal, &self.policies, sandbox_root)?;
        Err(PlatformError::Unsupported("show a file location"))
    }

    fn simulate_keys(&self, chord: &str) -> Result<(), PlatformError> {
        check_key_chord(chord)?;
        if !self.policies.allows_simulate_keys() {
            return Err(PlatformError::SimulateKeysNotGranted);
        }
        Err(PlatformError::Unsupported("simulate keys"))
    }

    fn write_clipboard(&self, text: &str) -> Result<(), PlatformError> {
        check_clipboard_text(text)?;
        Err(PlatformError::Unsupported("write to the clipboard"))
    }

    fn notify(&self, title: &str, body: &str) -> Result<(), PlatformError> {
        check_notification(title, body)?;
        Err(PlatformError::Unsupported("show a notification"))
    }

    fn supported_actions(&self) -> Vec<PlatformAction> {
        Vec::new()
    }
}
