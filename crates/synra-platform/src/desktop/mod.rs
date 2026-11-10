//! The desktop platform, as commands the operating system already has.

//!
//! # Why this is a command bridge rather than a Tauri integration
//!
//! Because every desktop behaviour this trait describes is already a program: `xdg-open` opens a URL or a file,
//! `notify-send` shows a notification, `xclip` reads and writes the clipboard. What a desktop *application* adds on
//! top — a tray icon, a window that owns the notification, a keystroke synthesised through the window manager — is
//! shell integration. Keeping that in the app avoids pulling Tauri or a WebView into this crate.
//!
//! So the split is: **the commands and the order they run in are here, and the process launch is a trait.** A desktop
//! application supplies a runner that goes through its own permission model; a test supplies one that records; and the
//! default `SystemRunner` owns bounded command jobs. The daemon selects a headless platform and refuses desktop effects.
//!
//! # What is checked here and cannot be checked by a runner
//!
//! The **policy**, and it is checked *before* the runner is reached. A test asserts exactly that: a URL with a
//! `javascript:` scheme, a path outside the sandbox, a key chord when the policy forbids one, a notification over the
//! rate limit — each is refused, and the runner is then asked to have seen nothing. A check that ran after the launch
//! would be a check that reported a window it had already opened.

use crate::error::PlatformError;

/// Launches a program.
///
/// # Why the arguments are separate
///
/// Because a command built as one string is a command where a URL containing a space becomes two arguments, and a URL
/// containing `;` becomes two commands. The runner takes the program and its arguments apart so that no caller of this
/// trait ever has to quote anything — quoting is where a shell injection lives, and the way not to have one is not to
/// build a string a shell will parse. Keep script bodies fixed; supply data through stdin or
/// through separate argv values after an explicit end-of-options marker.
pub trait CommandRunner: Send + Sync {
    /// Whether this provider can execute desktop commands on this host class.
    fn is_available(&self) -> bool;
    /// Runs a program with optional UTF-8 stdin and closes stdin after writing it.
    /// Implementations must bound execution and IO and preserve output instead of decoding lossily.
    ///
    /// # Errors
    ///
    /// [`PlatformError::RunnerFailed`] when the program could not be launched or exited non-zero, and
    /// [`PlatformError::Unsupported`] when the runner has no such capability — a WebView host with no process launch
    /// at all, say.
    /// [`PlatformError::RunnerBusy`] refuses excess jobs; [`PlatformError::RunnerTimedOut`] bounds waiting.
    /// [`PlatformError::RunnerOutputTooLong`] bounds stdout/stderr; [`PlatformError::TooLong`] bounds input/arguments.
    /// [`PlatformError::RunnerCleanupFailed`] keeps the unreaped process's job slot reserved.
    fn run(
        &self,
        program: &str,
        arguments: &[&str],
        input: Option<&str>,
    ) -> Result<String, PlatformError>;
}

mod powershell;
mod runner;

pub use runner::SystemRunner;

mod platform;
mod types;

pub use platform::CommandPlatform;
pub use types::Desktop;

#[cfg(test)]
#[path = "../desktop_tests.rs"]
mod tests;

