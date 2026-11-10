//! CommandPlatform policy checks and operating-system actions.

use std::time::Duration;

use crate::actions::{PlatformAction, Policies};
use crate::error::PlatformError;
use crate::guard::RateLimiter;
use crate::host::Platform;

use super::{CommandRunner, Desktop, SystemRunner};
use crate::desktop::powershell;

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
            .field(
                "notifications_per_hour",
                &self.policies.notifications_per_hour(),
            )
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
        Self {
            policies: Policies::new(),
            desktop,
            runner,
            limiter: RateLimiter::new(Policies::new()),
        }
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

    /// Copies the text currently selected in the focused desktop application and reads it back.
    ///
    /// This is used by an explicit user action. It keeps the key chord and clipboard read in one bounded platform
    /// operation, so callers do not accidentally read the clipboard before the focused application has handled Ctrl+C.
    pub fn read_selected_clipboard(&self) -> Result<Option<String>, PlatformError> {
        self.limiter
            .admit(PlatformAction::SimulateKeys, Self::now_ms())?;
        match self.desktop {
            Desktop::Linux => {
                let _ = self.run("xdotool", &["key", "--", "ctrl+c"])?;
            }
            Desktop::MacOs => {
                let _ = self.run(
                    "osascript",
                    &[
                        "-e",
                        "tell application \"System Events\" to keystroke \"c\" using {command down}",
                    ],
                )?;
            }
            Desktop::Windows => {
                let _ = self.powershell(powershell::KEYS, Some("ctrl+c"))?;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
        self.read_clipboard()
    }

    /// The milliseconds this platform reads the clock at.
    ///
    /// # Why the clock is read here rather than taken as an argument
    ///
    /// Because a rate limit whose clock came from the caller is a rate limit the caller can move. The two places that
    /// *are* driven by an argument are the tests, which pass a time explicitly — and that is why the limiter is a
    /// public type with a public method rather than something hidden inside this struct.
    pub(crate) fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_millis() as u64)
    }

    /// Runs a command, and maps the runner's refusals onto this platform's vocabulary.
    fn run(&self, program: &str, arguments: &[&str]) -> Result<String, PlatformError> {
        self.run_with_input(program, arguments, None)
    }

    pub(crate) fn run_with_input(
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


mod actions;

