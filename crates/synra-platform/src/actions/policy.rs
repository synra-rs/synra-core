use core::time::Duration;

use super::PlatformAction;

/// What the host allows.
///
/// Every field is a decision, and every default is the restrictive one. A host that wants to be permissive has to
/// say so, which is the opposite of a configuration whose defaults quietly allow whatever was added last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policies {
    /// Whether a plain-HTTP URL may be opened.
    ///
    /// Off: a URL the user is shown as "example.com" that arrives over HTTP can be rewritten in transit to
    /// something else, and the consent prompt's whole value is that it says where the user is going.
    pub(crate) allow_insecure_urls: bool,
    /// Whether `file:` and other non-web schemes may be opened.
    ///
    /// Off. `file:` names a path, and a path can be a program; the scheme is a way to reach
    /// [`Self::allow_executables`] without passing through it.
    pub(crate) allow_local_schemes: bool,
    /// Whether an executable extension may be opened.
    ///
    /// Off, and there is no configuration that turns it on. The field exists so the refusal is a value a test can
    /// read rather than a hard-coded branch.
    pub(crate) allow_executables: bool,
    /// Whether simulating keys is granted at all.
    ///
    /// Off, and the user turns it on from the settings screen. The design document requires it to be a separate,
    /// default-off authorisation.
    pub(crate) allow_simulate_keys: bool,
    /// Whether simulating keys requires the user to have interacted recently.
    ///
    /// On. A plugin that types while the user is elsewhere is acting without them — the design document's
    /// requirement that it "can only be called during a foreground interaction".
    pub(crate) require_foreground_for_keys: bool,
    /// How long ago the user's last interaction may be, when the check above is on.
    pub(crate) foreground_window: Duration,
    /// The shortest gap between two key chords.
    pub(crate) key_chord_interval: Duration,
    /// The shortest gap between two notifications.
    pub(crate) notification_interval: Duration,
    /// The most notifications allowed in one hour.
    pub(crate) notifications_per_hour: u32,
    /// Whether revealing a path is limited to the plugin's own sandbox.
    ///
    /// On. Revealing an arbitrary path tells the plugin what exists on the disk, which is information it was not
    /// given.
    pub(crate) restrict_reveal_to_sandbox: bool,
}

impl Default for Policies {
    fn default() -> Self {
        Self {
            allow_insecure_urls: false,
            allow_local_schemes: false,
            allow_executables: false,
            allow_simulate_keys: false,
            require_foreground_for_keys: true,
            foreground_window: Duration::from_secs(30),
            // Twenty a second is faster than a person types and slow enough that a runaway loop cannot fill
            // another application with input.
            key_chord_interval: Duration::from_millis(50),
            // One every thirty seconds, with an hourly ceiling: an application that notifies more often than that
            // is one whose notifications get turned off entirely.
            notification_interval: Duration::from_secs(30),
            notifications_per_hour: 20,
            restrict_reveal_to_sandbox: true,
        }
    }
}

impl Policies {
    /// The defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allows plain-HTTP URLs.
    ///
    /// # The cost
    ///
    /// The consent prompt shows the user a hostname. Over HTTP that hostname can be rewritten before the
    /// response, so the prompt is still true about the *destination* and false about what will be displayed —
    /// which is the thing the user is deciding about.
    #[must_use]
    pub const fn with_insecure_urls(mut self, allow: bool) -> Self {
        self.allow_insecure_urls = allow;
        self
    }

    /// Allows non-web schemes such as `file:`.
    #[must_use]
    pub const fn with_local_schemes(mut self, allow: bool) -> Self {
        self.allow_local_schemes = allow;
        self
    }

    /// Grants key simulation.
    ///
    /// The settings screen calls this, and only after an explicit user action. Nothing else may.
    #[must_use]
    pub const fn with_simulate_keys(mut self, allow: bool) -> Self {
        self.allow_simulate_keys = allow;
        self
    }

    /// Whether key simulation needs a recent interaction.
    #[must_use]
    pub const fn with_foreground_requirement(mut self, require: bool) -> Self {
        self.require_foreground_for_keys = require;
        self
    }

    /// Sets the window in which an interaction counts as recent.
    #[must_use]
    pub const fn with_foreground_window(mut self, window: Duration) -> Self {
        self.foreground_window = window;
        self
    }

    /// Sets the shortest gap between key chords.
    #[must_use]
    pub const fn with_key_chord_interval(mut self, interval: Duration) -> Self {
        self.key_chord_interval = interval;
        self
    }

    /// Sets the shortest gap between notifications.
    #[must_use]
    pub const fn with_notification_interval(mut self, interval: Duration) -> Self {
        self.notification_interval = interval;
        self
    }

    /// Sets the hourly notification ceiling.
    #[must_use]
    pub const fn with_notifications_per_hour(mut self, count: u32) -> Self {
        self.notifications_per_hour = count;
        self
    }

    /// Lifts the sandbox restriction on revealing paths.
    #[must_use]
    pub const fn with_reveal_outside_sandbox(mut self, allow: bool) -> Self {
        self.restrict_reveal_to_sandbox = !allow;
        self
    }

    /// Whether plain-HTTP URLs are allowed.
    #[must_use]
    pub const fn allows_insecure_urls(&self) -> bool {
        self.allow_insecure_urls
    }

    /// Whether non-web schemes such as `file:` are allowed.
    #[must_use]
    pub const fn allows_local_schemes(&self) -> bool {
        self.allow_local_schemes
    }

    /// Whether key simulation is granted.
    #[must_use]
    pub const fn allows_simulate_keys(&self) -> bool {
        self.allow_simulate_keys
    }

    /// The window in which an interaction counts as recent.
    #[must_use]
    pub const fn foreground_window(&self) -> Duration {
        self.foreground_window
    }

    /// The shortest gap between key chords.
    #[must_use]
    pub const fn key_chord_interval(&self) -> Duration {
        self.key_chord_interval
    }

    /// The shortest gap between notifications.
    #[must_use]
    pub const fn notification_interval(&self) -> Duration {
        self.notification_interval
    }

    /// The hourly notification ceiling.
    #[must_use]
    pub const fn notifications_per_hour(&self) -> u32 {
        self.notifications_per_hour
    }

    /// Whether revealing a path is limited to the plugin's sandbox.
    #[must_use]
    pub const fn restricts_reveal_to_sandbox(&self) -> bool {
        self.restrict_reveal_to_sandbox
    }

    /// What the consent screen says a grant would allow.
    ///
    /// Composed from the policy rather than written per action, so a policy change cannot leave the prompt
    /// describing something the host no longer does.
    #[must_use]
    pub fn describe(&self, action: PlatformAction) -> String {
        let risk = action.risk();
        match action {
            PlatformAction::OpenUrl if !self.allow_insecure_urls => {
                format!("{risk}; only https addresses are allowed")
            }
            PlatformAction::SimulateKeys if !self.allow_simulate_keys => {
                format!("{risk} — this is turned off and has to be enabled in settings")
            }
            PlatformAction::RevealPath if self.restrict_reveal_to_sandbox => {
                format!("{risk}; only inside its own data directory")
            }
            _ => risk.to_owned(),
        }
    }
}
