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

use std::path::Path;

use crate::actions::{MAX_CLIPBOARD_BYTES, PlatformAction, Policies};
use crate::error::PlatformError;
use crate::guard::{
    PathUse, RateLimiter, check_clipboard_text, check_key_chord, check_notification, check_path,
    check_url,
};
use crate::host::Platform;

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

/// Which desktop this is, which decides which programs exist.
///
/// # Why this is a value and not `cfg!`
///
/// Because it has to be *testable*: the command a Windows host runs for "reveal this file in the file manager" is a
/// fact worth asserting, and a compile-time branch cannot be asserted on the other platforms. It is also what makes
/// the choice a caller's: a Linux desktop running a Windows-targeted build is not a thing, but a test driving the
/// Windows command table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Desktop {
    /// Linux, and the BSDs that keep the same tools.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Desktop {
    /// The desktop this build is running on.
    ///
    /// The `cfg` is here and nowhere else, so that everything decided *from* it is ordinary code a test can drive.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        }
        else if cfg!(target_os = "macos") {
            Self::MacOs
        }
        else {
            Self::Linux
        }
    }

    /// A name, for a log line and a health screen.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }

    /// The program that opens a URL or a file with whatever handles it.
    #[must_use]
    pub const fn opener(self) -> &'static str {
        match self {
            Self::Linux => "xdg-open",
            Self::MacOs => "open",
            Self::Windows => "explorer",
        }
    }

    /// The program that shows a file in the file manager, when it is not the opener.
    ///
    /// Windows is the one that differs: `explorer /select,` is how a file is highlighted rather than opened, and
    /// `xdg-open` and `open -R` would open a directory instead of showing the file inside it.
    #[must_use]
    pub const fn revealer(self) -> (&'static str, &'static str) {
        match self {
            Self::Linux => ("xdg-open", ""),
            Self::MacOs => ("open", "-R"),
            // `/select,` is one argument with a trailing comma and no space: an `explorer` invocation that separates
            // them is one Windows parses as a path called `/select`.
            Self::Windows => ("explorer", "/select,"),
        }
    }
}

/// The desktop platform: the checks, and the commands that carry them out.
pub struct CommandPlatform {
    policies: Policies,
    desktop: Desktop,
    runner: Box<dyn CommandRunner>,
    limiter: RateLimiter,
}

impl std::fmt::Debug for CommandPlatform {
    /// Names the desktop and the policies rather than the runner.
    ///
    /// The runner is a `dyn` trait with no `Debug` bound, deliberately: an application's runner may hold a window
    /// handle or a permission context, and requiring `Debug` of it would make every implementation carry formatting it
    /// has no use for. What a bug report needs is which desktop decided the programs and what was allowed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandPlatform")
            .field("desktop", &self.desktop)
            .field("simulate_keys", &self.policies.allows_simulate_keys())
            .field("notifications_per_hour", &self.policies.notifications_per_hour())
            .finish_non_exhaustive()
    }
}

impl CommandPlatform {
    /// A platform for the desktop this build runs on, launching programs directly.
    #[must_use]
    pub fn new() -> Self {
        Self::with(Desktop::current(), Box::new(SystemRunner::default()))
    }

    /// A platform for a desktop, with a runner.
    #[must_use]
    pub fn with(desktop: Desktop, runner: Box<dyn CommandRunner>) -> Self {
        Self { policies: Policies::new(), desktop, runner, limiter: RateLimiter::new(Policies::new()) }
    }

    /// The same platform with other policies.
    ///
    /// The limiter is rebuilt from them, because the interval and the hourly count are what it enforces: a limiter
    /// left over from the old policies would enforce the ones nobody chose.
    #[must_use]
    pub fn with_policies(mut self, policies: Policies) -> Self {
        self.limiter = RateLimiter::new(policies.clone());
        self.policies = policies;
        self
    }

    /// Which desktop this is.
    #[must_use]
    pub const fn desktop(&self) -> Desktop {
        self.desktop
    }

    /// How many notifications this platform is still allowed this hour.
    #[must_use]
    pub fn notifications_remaining(&self, now_ms: u64) -> u32 {
        self.policies
            .notifications_per_hour()
            .saturating_sub(self.limiter.notifications_in_window(now_ms))
    }

    /// The milliseconds this platform reads the clock at.
    ///
    /// # Why the clock is read here rather than taken as an argument
    ///
    /// Because a rate limit whose clock came from the caller is a rate limit the caller can move. The two places that
    /// *are* driven by an argument are the tests, which pass a time explicitly — and that is why the limiter is a
    /// public type with a public method rather than something hidden inside this struct.
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64)
    }

    /// Runs a command, and maps the runner's refusals onto this platform's vocabulary.
    fn run(&self, program: &str, arguments: &[&str]) -> Result<String, PlatformError> {
        self.run_with_input(program, arguments, None)
    }

    fn run_with_input(
        &self,
        program: &str,
        arguments: &[&str],
        input: Option<&str>,
    ) -> Result<String, PlatformError> {
        if !self.runner.is_available() {
            return Err(PlatformError::Unsupported(
                "execute desktop commands on this host",
            ));
        }
        self.runner.run(program, arguments, input)
    }

    /// Shows a notification with whichever program this desktop has.
    ///
    /// # Why the title and the body are one argument
    ///
    /// Because `notify-send` takes them as two and `osascript` takes a sentence — and the sentence is built from
    /// strings the guest supplied, so it is *not* built by interpolation into a script. The AppleScript is a fixed
    /// program that reads its two arguments from `argv`, which is the only way a plugin's notification text can reach
    /// it without becoming AppleScript.
    fn notify_with(&self, title: &str, body: &str) -> Result<(), PlatformError> {
        match self.desktop {
            Desktop::Linux => {
                let _ = self.run("notify-send", &["--", title, body])?;
                Ok(())
            }
            Desktop::MacOs => {
                let _ = self.run(
                    "osascript",
                    &[
                        "-e",
                        "on run argv",
                        "-e",
                        "display notification (item 2 of argv) with title (item 1 of argv)",
                        "-e",
                        "end run",
                        "--",
                        title,
                        body,
                    ],
                )?;
                Ok(())
            }
            Desktop::Windows => {
                let input = serde_json::json!({ "title": title, "body": body }).to_string();
                let _ = self.powershell(powershell::NOTIFY, Some(&input))?;
                Ok(())
            }
        }
    }
}

impl Default for CommandPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for CommandPlatform {
    fn name(&self) -> &'static str {
        // The name a log line and a health screen show, and it names the desktop because that is what decides which
        // programs run.
        match self.desktop {
            Desktop::Linux => "desktop-linux",
            Desktop::MacOs => "desktop-macos",
            Desktop::Windows => "desktop-windows",
        }
    }

    fn policies(&self) -> &Policies {
        &self.policies
    }

    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        // ★ The check first, and the runner second. A check that ran after the launch would be a check that reported a
        // window it had already opened.
        check_url(url, &self.policies)?;
        self.limiter.admit(PlatformAction::OpenUrl, Self::now_ms())?;
        let _ = self.run(self.desktop.opener(), &[url])?;
        Ok(())
    }

    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        check_path(path, PathUse::Open, &self.policies, None)?;
        self.limiter.admit(PlatformAction::OpenPath, Self::now_ms())?;
        let text = path.to_string_lossy().to_string();
        let _ = self.run(self.desktop.opener(), &[text.as_str()])?;
        Ok(())
    }

    fn reveal_path(&self, path: &Path, sandbox_root: Option<&Path>) -> Result<(), PlatformError> {
        // The sandbox root is what stops a plugin revealing `~/.ssh` in a file manager the user is looking at.
        check_path(path, PathUse::Reveal, &self.policies, sandbox_root)?;
        self.limiter.admit(PlatformAction::RevealPath, Self::now_ms())?;
        let text = path.to_string_lossy().to_string();
        let (program, flag) = self.desktop.revealer();
        let arguments: Vec<&str> = if flag.is_empty() { vec![text.as_str()] } else { vec![flag, text.as_str()] };
        let _ = self.run(program, &arguments)?;
        Ok(())
    }

    fn simulate_keys(&self, chord: &str) -> Result<(), PlatformError> {
        check_key_chord(chord)?;
        if !self.policies.allows_simulate_keys() {
            return Err(PlatformError::SimulateKeysNotGranted);
        }
        // ★ The rate limit is the whole of the protection here: a plugin that can type into whatever window is focused
        // can do anything the user can, and the interval is what makes it a slow, visible thing rather than a
        // keystroke storm.
        self.limiter.admit(PlatformAction::SimulateKeys, Self::now_ms())?;
        match self.desktop {
            Desktop::Linux => {
                let _ = self.run("xdotool", &["key", "--", chord])?;
            }
            Desktop::MacOs => {
                // A fixed program that reads the chord from `argv`, for the same reason the notification does.
                let _ = self.run(
                    "osascript",
                    &[
                        "-e",
                        "on run argv",
                        "-e",
                        "tell application \"System Events\" to keystroke (item 1 of argv)",
                        "-e",
                        "end run",
                        "--",
                        chord,
                    ],
                )?;
            }
            Desktop::Windows => {
                let _ = self.powershell(powershell::KEYS, Some(chord))?;
            }
        }
        Ok(())
    }

    fn read_clipboard(&self) -> Result<Option<String>, PlatformError> {
        self.limiter.admit(PlatformAction::ReadClipboard, Self::now_ms())?;
        let text: Option<String> = match self.desktop {
            Desktop::Linux => Some(self.run("xclip", &["-selection", "clipboard", "-o"])?),
            Desktop::MacOs => Some(self.run("pbpaste", &[])?),
            Desktop::Windows => {
                let answer = self.powershell(powershell::READ, None)?;
                serde_json::from_str(&answer).map_err(|_| PlatformError::RunnerFailed {
                    program: "powershell".to_owned(),
                    reason: "clipboard response is not nullable text JSON".to_owned(),
                })?
            }
        };
        if text
            .as_ref()
            .is_some_and(|text| text.len() > MAX_CLIPBOARD_BYTES)
        {
            return Err(PlatformError::RunnerOutputTooLong {
                program: "clipboard backend".to_owned(),
                stream: "decoded clipboard text",
                max: MAX_CLIPBOARD_BYTES,
            });
        }
        Ok(text)
    }

    fn write_clipboard(&self, text: &str) -> Result<(), PlatformError> {
        check_clipboard_text(text)?;
        self.limiter.admit(PlatformAction::WriteClipboard, Self::now_ms())?;
        match self.desktop {
            Desktop::Linux => {
                let _ =
                    self.run_with_input("xclip", &["-selection", "clipboard", "-in"], Some(text))?;
            }
            Desktop::MacOs => {
                let _ = self.run_with_input("pbcopy", &[], Some(text))?;
            }
            Desktop::Windows => {
                let _ = self.powershell(powershell::WRITE, Some(text))?;
            }
        }
        Ok(())
    }

    fn notify(&self, title: &str, body: &str) -> Result<(), PlatformError> {
        check_notification(title, body)?;
        // The limiter is what a notification has instead of a permission: it is user-visible, so the risk is being
        // annoying rather than being dangerous.
        self.limiter.admit(PlatformAction::Notify, Self::now_ms())?;
        self.notify_with(title, body)
    }

    fn supported_actions(&self) -> Vec<PlatformAction> {
        if !self.runner.is_available() {
            return Vec::new();
        }
        // ★ The list an interface draws its menu from, and it is the *askable* list rather than the implemented one:
        // `SimulateKeys` is offered when the policy allows it, because a menu item that is never available is worse
        // than one that explains why it is not.
        let mut actions = vec![
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::Notify,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
        ];
        if self.policies.allows_simulate_keys() {
            actions.push(PlatformAction::SimulateKeys);
        }
        actions
    }
}

#[cfg(test)]
#[path = "desktop_tests.rs"]
mod tests;
