//! Host system capabilities, and the rules that bound them.
//!
//! # This is the most dangerous surface in the application
//!
//! Everything else a plugin can do is mediated: `device:send` goes to another Synra device, `fs:write` goes into
//! a sandbox directory, `network:fetch` goes through a host that can refuse a hostname. `platform:*` goes to the
//! user's actual machine — it opens their browser, types into their other applications, reads their clipboard.
//!
//! A bug here is not a plugin misbehaving inside its own boundaries. It is a plugin acting as the user.
//!
//! # The rules are values, not calls
//!
//! [`Policies`] holds every decision — whether an executable may be opened, whether a plain-HTTP URL is allowed,
//! how often a notification may fire — and [`Platform::check`] answers yes or no without touching the operating
//! system. That shape is deliberate: the interesting part of this module is *whether a call should happen*, and
//! a design that only answers that question by attempting the call is a design whose rules cannot be tested.
//!
//! So there are two halves:
//!
//! * **Decide** — [`Policies::check`] and friends. Pure, exhaustively tested, and the place where a mistake is a
//!   unit test rather than an incident.
//! * **Act** — the [`Platform`] trait. Thin, unimplemented here, and implemented by the application layer over
//!   Tauri.
//!
//! # Every action is separate, and none is implied by another
//!
//! `platform:clipboard:read` is not `platform:clipboard:write` plus a read. `platform:open-url` does not imply
//! `platform:open-path` — the second can run a file, the first cannot. A caller asks about the exact action it is
//! about to perform, because an authorisation that covers "the clipboard" is one a user granted for a different
//! reason.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. The relaxation has to live
// at the crate root, because the workspace sets these lints to `deny` and a local `#[allow]` cannot override a
// `deny` set at a higher priority level.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]
use core::fmt;
use core::time::Duration;
use std::path::Path;

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
            Self::ReadClipboard => "platform:clipboard:read",
            Self::WriteClipboard => "platform:clipboard:write",
            Self::Notify => "platform:notify",
        }
    }

    /// Whether the action has an effect the user can see while it happens.
    ///
    /// The three that do: a browser window, a file manager, a notification. The others are silent, which is why
    /// they need something else — see [`Self::needs_visible_indicator`].
    #[must_use]
    pub const fn is_user_visible(self) -> bool {
        matches!(self, Self::OpenUrl | Self::OpenPath | Self::RevealPath | Self::Notify)
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
            Self::SimulateKeys => {
                "can type into your other applications, as if you were typing"
            }
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
    "exe", "com", "bat", "cmd", "msi", "msp", "scr", "pif", "cpl", "hta", "jar", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "lnk", "inf", "reg", "dll", "sys", "ocx",
    // Unix and macOS
    "sh", "bash", "zsh", "fish", "run", "bin", "app", "command", "workflow", "scpt", "desktop", "so", "dylib",
    // Anything that installs or configures
    "pkg", "dmg", "deb", "rpm", "appimage", "apk",
];

/// The longest a URL may be.
pub const MAX_URL_LEN: usize = 8 * 1024;

/// The longest a notification's title or body may be.
pub const MAX_NOTIFICATION_LEN: usize = 512;

/// The longest a key chord may be.
pub const MAX_CHORD_LEN: usize = 128;

/// The longest clipboard content a plugin may read.
///
/// Bounded because a clipboard can hold megabytes — an image, a whole document — and a plugin that asked for it
/// would be handed the user's data in bulk. A plugin wanting a large object uses `file.transfer`, which the user
/// can see and cancel.
pub const MAX_CLIPBOARD_BYTES: usize = 256 * 1024;

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
    allow_insecure_urls: bool,
    /// Whether `file:` and other non-web schemes may be opened.
    ///
    /// Off. `file:` names a path, and a path can be a program; the scheme is a way to reach
    /// [`Self::allow_executables`] without passing through it.
    allow_local_schemes: bool,
    /// Whether an executable extension may be opened.
    ///
    /// Off, and there is no configuration that turns it on. The field exists so the refusal is a value a test can
    /// read rather than a hard-coded branch.
    allow_executables: bool,
    /// Whether simulating keys is granted at all.
    ///
    /// Off, and the user turns it on from the settings screen. The design document requires it to be a separate,
    /// default-off authorisation.
    allow_simulate_keys: bool,
    /// Whether simulating keys requires the user to have interacted recently.
    ///
    /// On. A plugin that types while the user is elsewhere is acting without them — the design document's
    /// requirement that it "can only be called during a foreground interaction".
    require_foreground_for_keys: bool,
    /// How long ago the user's last interaction may be, when the check above is on.
    foreground_window: Duration,
    /// The shortest gap between two key chords.
    key_chord_interval: Duration,
    /// The shortest gap between two notifications.
    notification_interval: Duration,
    /// The most notifications allowed in one hour.
    notifications_per_hour: u32,
    /// Whether revealing a path is limited to the plugin's own sandbox.
    ///
    /// On. Revealing an arbitrary path tells the plugin what exists on the disk, which is information it was not
    /// given.
    restrict_reveal_to_sandbox: bool,
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

/// Why a platform action was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The URL is not one the host will open.
    #[error("the address {url:?} cannot be opened: {reason}")]
    BadUrl {
        /// The URL, as supplied.
        url: String,
        /// Why not.
        reason: UrlRefusal,
    },

    /// The path is not one the host will open or reveal.
    #[error("the path {path:?} cannot be used: {reason}")]
    BadPath {
        /// The path, as supplied.
        path: String,
        /// Why not.
        reason: PathRefusal,
    },

    /// Key simulation is not granted.
    #[error("simulating keys is not enabled; the user has to turn it on in settings")]
    SimulateKeysNotGranted,

    /// The user is not interacting, so a plugin may not type on their behalf.
    #[error("keys cannot be simulated: the last interaction was {elapsed_ms}ms ago")]
    NoRecentInteraction {
        /// How long ago the user last interacted.
        elapsed_ms: u64,
    },

    /// A rate limit was hit.
    #[error("{action} was called too soon: {remaining_ms}ms to wait")]
    RateLimited {
        /// Which action.
        action: PlatformAction,
        /// How long until another call is allowed.
        remaining_ms: u64,
    },

    /// An action was requested more times than the hourly ceiling allows.
    #[error("{action} has been used {used} times this hour, and the limit is {limit}")]
    QuotaExceeded {
        /// Which action.
        action: PlatformAction,
        /// How many times it has been used.
        used: u32,
        /// The ceiling.
        limit: u32,
    },

    /// A value is too long.
    #[error("the {field} is {len} characters, and the limit is {max}")]
    TooLong {
        /// Which field.
        field: &'static str,
        /// How long it is.
        len: usize,
        /// The limit.
        max: usize,
    },

    /// The operating system refused, or the request was one the host will not pass on.
    ///
    /// A `&'static str` rather than a `String`: the variant carries a description of the operation that was
    /// refused, which is a fixed phrase in this crate, and it never carries anything a caller supplied — a message
    /// built from a plugin's input is how a refusal becomes a way to put text in front of the user.
    #[error("the system refused to {0}")]
    Unavailable(&'static str),

    /// This host cannot perform the action at all.
    ///
    /// Not a failure: a headless host has no clipboard, and a `synra doctor` run on a server-like build has no
    /// browser. The distinction matters because the caller's response differs — one is a configuration problem
    /// and the other is not.
    #[error("this host cannot {0}")]
    Unsupported(&'static str),
}

/// Why a URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum UrlRefusal {
    /// It is empty.
    Empty,
    /// It is longer than [`MAX_URL_LEN`].
    TooLong,
    /// It has no scheme.
    NoScheme,
    /// It uses a scheme that names something local.
    LocalScheme,
    /// It is plain HTTP, and insecure URLs are not allowed.
    Insecure,
    /// It has no host.
    NoHost,
    /// It contains a control character, which could be used to forge a prompt or a log line.
    ControlCharacter,
}

impl fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.explain())
    }
}

impl UrlRefusal {
    /// A sentence for the user.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Empty => "the address is empty",
            Self::TooLong => "the address is too long",
            Self::NoScheme => "the address has no scheme",
            Self::LocalScheme => "the address names something on this computer, which is not a web page",
            Self::Insecure => "the address is not secure, so what it shows could be changed in transit",
            Self::NoHost => "the address has no host",
            Self::ControlCharacter => "the address contains an invisible character",
        }
    }
}

/// Why a path was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PathRefusal {
    /// It is empty.
    Empty,
    /// It is not absolute, so what it names depends on the working directory.
    NotAbsolute,
    /// It has no extension and no way to tell what it is, which for `open-path` means it cannot be proven not to
    /// be a program.
    UnknownKind,
    /// Its extension marks it as executable or installable.
    Executable,
    /// It is outside the plugin's sandbox, and revealing it would disclose what exists on the disk.
    OutsideSandbox,
    /// It contains a control character.
    ControlCharacter,
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.explain())
    }
}

impl PathRefusal {
    /// A sentence for the user.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Empty => "the path is empty",
            Self::NotAbsolute => "the path is relative, so it depends on where the application is running",
            Self::UnknownKind => "the path has no extension, so there is no way to tell what it is",
            Self::Executable => "the path is a program or an installer, and opening it would run it",
            Self::OutsideSandbox => "the path is outside the plugin's own data directory",
            Self::ControlCharacter => "the path contains an invisible character",
        }
    }
}

/// Checks a URL against the policies, without opening it.
///
/// # Errors
///
/// [`PlatformError::BadUrl`] or [`PlatformError::TooLong`].
pub fn check_url(url: &str, policies: &Policies) -> Result<(), PlatformError> {
    if url.len() > MAX_URL_LEN {
        return Err(bad_url(url, UrlRefusal::TooLong));
    }
    if url.is_empty() {
        return Err(bad_url(url, UrlRefusal::Empty));
    }
    // A control character could forge the consent prompt's text, or split a log line, so it is refused before
    // anything else looks at the string.
    if url.chars().any(char::is_control) {
        return Err(bad_url(url, UrlRefusal::ControlCharacter));
    }

    let Some((scheme, rest)) = url.split_once(':') else {
        return Err(bad_url(url, UrlRefusal::NoScheme));
    };
    let scheme = scheme.to_ascii_lowercase();

    match scheme.as_str() {
        "https" => {}
        "http" if policies.allow_insecure_urls => {}
        "http" => return Err(bad_url(url, UrlRefusal::Insecure)),
        // Everything that is not a web scheme names something local or is handled by another program, and the
        // list is closed rather than "anything not http": `javascript:`, `data:` and `vbscript:` are all things a
        // plugin could put in an "open this link" prompt.
        _ => {
            if !policies.allow_local_schemes {
                return Err(bad_url(url, UrlRefusal::LocalScheme));
            }
        }
    }

    // A web address must name a host: `https:///x` and `https://?q` both have an empty authority, and the consent
    // prompt's whole value is that it says where the user is going.
    //
    // A non-web scheme is not checked this way, because having no host is ordinary for it — `file:///etc/passwd`
    // has an empty authority and names a path. Such a scheme reached this point only because the policy allows
    // local schemes, so the user has already agreed to the class of thing; demanding a host would refuse the
    // common spelling of exactly what they allowed.
    if matches!(scheme.as_str(), "http" | "https") {
        let authority = rest.trim_start_matches("//");
        let host_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        let host = authority.get(..host_end).unwrap_or_default();
        if host.is_empty() {
            return Err(bad_url(url, UrlRefusal::NoHost));
        }
    }

    Ok(())
}

/// Builds a URL refusal.
fn bad_url(url: &str, reason: UrlRefusal) -> PlatformError {
    PlatformError::BadUrl { url: url.to_owned(), reason }
}

/// How a path is being used, which decides which checks apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathUse {
    /// Opened with the default application, so an executable would run.
    Open,
    /// Shown in the file manager, which does not run anything.
    Reveal,
}

/// Checks a path against the policies.
///
/// # Errors
///
/// [`PlatformError::BadPath`] describing the first refusal.
///
/// # Absolute paths only
///
/// A relative path is checked against the working directory, which for a plugin's call is whichever thread the
/// host happened to be on. The same call would then open different files at different times, and the consent
/// prompt could not say which.
pub fn check_path(
    path: &Path,
    path_use: PathUse,
    policies: &Policies,
    sandbox_root: Option<&Path>,
) -> Result<(), PlatformError> {
    let text = path.to_string_lossy();
    let refuse = |reason: PathRefusal| PlatformError::BadPath { path: text.to_string(), reason };

    if text.is_empty() {
        return Err(refuse(PathRefusal::Empty));
    }
    if text.chars().any(char::is_control) {
        return Err(refuse(PathRefusal::ControlCharacter));
    }
    if !path.is_absolute() {
        return Err(refuse(PathRefusal::NotAbsolute));
    }

    if path_use == PathUse::Reveal && policies.restrict_reveal_to_sandbox {
        match sandbox_root {
            Some(root) => {
                // Component-wise, because `/data` is a string prefix of `/database`.
                if !synra_store::is_within(root, path) {
                    return Err(refuse(PathRefusal::OutsideSandbox));
                }
            }
            // No sandbox supplied and the policy restricts to one means the check cannot be made, and a check
            // that cannot be made is not a check that passed.
            None => return Err(refuse(PathRefusal::OutsideSandbox)),
        }
    }

    if path_use == PathUse::Open && !policies.allow_executables {
        // The list is by extension, and a path with no extension is refused too: the check's purpose is to prove
        // a file is not a program, and with no extension there is nothing to prove it with.
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
        {
            Some(extension) => {
                if EXECUTABLE_EXTENSIONS.contains(&extension.as_str()) {
                    return Err(refuse(PathRefusal::Executable));
                }
            }
            None => return Err(refuse(PathRefusal::UnknownKind)),
        }
    }

    Ok(())
}

/// Checks a URL's length for a caller building one, so the failure happens before the open.
///
/// # Errors
///
/// [`PlatformError::TooLong`].
pub const fn check_url_length(url: &str) -> Result<(), PlatformError> {
    if url.len() > MAX_URL_LEN {
        return Err(PlatformError::TooLong { field: "address", len: url.len(), max: MAX_URL_LEN });
    }
    Ok(())
}

/// Checks a notification's text.
///
/// # Errors
///
/// [`PlatformError::TooLong`].
pub fn check_notification(title: &str, body: &str) -> Result<(), PlatformError> {
    for (field, text) in [("notification title", title), ("notification body", body)] {
        let len = text.chars().count();
        if len > MAX_NOTIFICATION_LEN {
            return Err(PlatformError::TooLong { field, len, max: MAX_NOTIFICATION_LEN });
        }
    }
    Ok(())
}

/// Checks a key chord.
///
/// # Errors
///
/// [`PlatformError::TooLong`] or [`PlatformError::Unavailable`] for a chord with no keys in it.
pub fn check_key_chord(chord: &str) -> Result<(), PlatformError> {
    let len = chord.chars().count();
    if len > MAX_CHORD_LEN {
        return Err(PlatformError::TooLong { field: "key chord", len, max: MAX_CHORD_LEN });
    }
    // An empty chord is not "no keys", it is a call that does nothing — and a loop of them would still hold the
    // rate limiter's attention.
    if chord.trim().is_empty() {
        return Err(PlatformError::Unavailable("simulate an empty key chord"));
    }
    Ok(())
}

/// Decides whether an action may proceed, given how it has been used.
///
/// A rate limiter rather than a scheduler: it answers "may this happen now" and records the answer, and the
/// caller supplies the clock. Keeping the clock out means the limits can be tested without sleeping.
#[derive(Debug)]
pub struct RateLimiter {
    policies: Policies,
    /// The last time each rate-limited action ran.
    last: parking_lot::Mutex<std::collections::HashMap<PlatformAction, u64>>,
    /// A sliding window of notification times, for the hourly ceiling.
    notifications: parking_lot::Mutex<Vec<u64>>,
}

impl RateLimiter {
    /// A limiter with the given policies.
    #[must_use]
    pub fn new(policies: Policies) -> Self {
        Self {
            policies,
            last: parking_lot::Mutex::new(std::collections::HashMap::new()),
            notifications: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// The policies in force.
    #[must_use]
    pub const fn policies(&self) -> &Policies {
        &self.policies
    }

    /// Checks an action and records it, at `now_ms`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::RateLimited`] or [`PlatformError::QuotaExceeded`].
    pub fn admit(&self, action: PlatformAction, now_ms: u64) -> Result<(), PlatformError> {
        let interval = match action {
            PlatformAction::SimulateKeys => self.policies.key_chord_interval,
            PlatformAction::Notify => self.policies.notification_interval,
            // Everything else is bounded by the action's own cost or by a capability the user granted once; a
            // rate limit on `open-url` would refuse a legitimate burst of links a user clicked.
            _ => return Ok(()),
        };
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);

        if action == PlatformAction::Notify {
            let mut times = self.notifications.lock();
            // The window is one hour, and entries older than that are dropped rather than counted: a fixed
            // window would let a plugin fire the whole ceiling at the end of one hour and again at the start of
            // the next.
            times.retain(|at| now_ms.saturating_sub(*at) < 3_600_000);
            let limit = self.policies.notifications_per_hour;
            if times.len() >= limit as usize {
                return Err(PlatformError::QuotaExceeded {
                    action,
                    used: u32::try_from(times.len()).unwrap_or(u32::MAX),
                    limit,
                });
            }
            times.push(now_ms);
        }

        // The decision is made inside a block so the guard is released before the `return`. Holding a lock across
        // an early return is a borrowed-scrutinee that `clippy::correctness` refuses, and the fix is the code's
        // shape rather than an annotation: the lock's job is to read one entry, not to span the rest of the
        // function.
        {
            let mut last = self.last.lock();
            let outcome = match last.get(&action) {
                Some(previous) => {
                    let elapsed = now_ms.saturating_sub(*previous);
                    if elapsed < interval_ms {
                        Err(PlatformError::RateLimited {
                            action,
                            remaining_ms: interval_ms - elapsed,
                        })
                    }
                    else {
                        Ok(())
                    }
                }
                None => Ok(()),
            };
            if outcome.is_ok() {
                last.insert(action, now_ms);
            }
            outcome
        }
    }

    /// Forgets a rate-limited action's history.
    ///
    /// For a test, and for a caller that knows the clock jumped — a device resuming from suspend has a
    /// monotonic clock that did not advance, and the alternative to forgetting is a plugin that cannot notify
    /// until the process restarts.
    pub fn forget(&self, action: PlatformAction) {
        self.last.lock().remove(&action);
        if action == PlatformAction::Notify {
            self.notifications.lock().clear();
        }
    }

    /// How many notifications were recorded inside the window ending at `now_ms`.
    #[must_use]
    pub fn notifications_in_window(&self, now_ms: u64) -> u32 {
        let mut times = self.notifications.lock();
        times.retain(|at| now_ms.saturating_sub(*at) < 3_600_000);
        u32::try_from(times.len()).unwrap_or(u32::MAX)
    }
}

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
        let len = text.chars().count();
        if len > MAX_NOTIFICATION_LEN * 4 {
            return Err(PlatformError::TooLong {
                field: "clipboard text",
                len,
                max: MAX_NOTIFICATION_LEN * 4,
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// A directory that is absolute on the platform running the test.
    ///
    /// Not a literal `/tmp`: on Windows that is *drive-relative* — it names the root of whichever drive is current —
    /// so `Path::is_absolute` is false for it and every path test would exercise the wrong branch.
    fn absolute_base() -> &'static str {
        if cfg!(windows) { "C:\\tmp" } else { "/tmp" }
    }

    /// An absolute path under the base directory.
    fn absolute(name: &str) -> std::path::PathBuf {
        Path::new(absolute_base()).join(name)
    }

    /// A path literal that is absolute on this platform, for the cases that take a `&str`.
    fn absolute_text(name: &str) -> String {
        absolute(name).display().to_string()
    }

    /// A plugin's sandbox root, absolute on this platform.
    fn sandbox_root() -> std::path::PathBuf {
        absolute("sandbox")
    }

    /// A directory that shares a string prefix with [`sandbox_root`] but is not inside it.
    ///
    /// The case a string-prefix containment check gets wrong, kept as a named helper so every test that needs it
    /// uses the same shape.
    fn sibling_root() -> std::path::PathBuf {
        absolute("sandbox-other")
    }

    // ── Actions ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_action_has_its_own_capability() {
        // An authorisation that covered "the platform" would be one a user granted for a different reason. Each
        // action names exactly one effect, and none implies another.
        let actions = [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ];
        let mut capabilities = std::collections::HashSet::new();
        for action in actions {
            let capability = action.capability();
            assert!(capabilities.insert(capability), "{capability} is shared");
            assert!(capability.starts_with("platform:"), "{capability}");
        }
        // Reading and writing the clipboard are separate grants.
        assert_ne!(
            PlatformAction::ReadClipboard.capability(),
            PlatformAction::WriteClipboard.capability()
        );
        // And opening a file is not opening a URL: the first can run a program.
        assert_ne!(PlatformAction::OpenUrl.capability(), PlatformAction::OpenPath.capability());
    }

    #[test]
    fn only_simulating_keys_is_off_by_default() {
        // It is the one action that lets a plugin drive other applications, and the design document requires it to
        // be a separate, default-off authorisation.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            assert!(!action.is_off_by_default(), "{action}");
        }
        assert!(PlatformAction::SimulateKeys.is_off_by_default());
    }

    #[test]
    fn the_silent_actions_are_the_ones_needing_an_indicator() {
        // A browser window announces itself. Reading the clipboard and typing do not, which is why they need
        // something else.
        assert!(PlatformAction::SimulateKeys.needs_visible_indicator());
        assert!(PlatformAction::ReadClipboard.needs_visible_indicator());
        assert!(!PlatformAction::WriteClipboard.needs_visible_indicator());
        assert!(!PlatformAction::Notify.needs_visible_indicator());
        // And the visible ones do not need an extra indicator, because they are their own.
        assert!(PlatformAction::OpenUrl.is_user_visible());
        assert!(!PlatformAction::SimulateKeys.is_user_visible());
    }

    #[test]
    fn every_action_names_its_risk() {
        // The consent screen is where a user decides, so a variant without a sentence is one the interface cannot
        // render.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            let risk = action.risk();
            assert!(risk.len() > 20, "{action} -> {risk}");
        }
    }

    #[test]
    fn action_capabilities_parse_as_capabilities() {
        // The names have to be ones the capability DSL accepts, or a manifest cannot request them.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            // `synra-capability` is not a dependency here, so the check is the character set its grammar allows,
            // taken from the same constant: `[A-Za-z0-9._@/*-]` per segment, with a `:` between segments.
            let capability = action.capability();
            let (domain, rest) = capability.split_once(':').expect("has a domain");
            assert_eq!(domain, "platform");
            assert!(!rest.is_empty());
            for segment in rest.split(':') {
                assert!(!segment.is_empty(), "{capability}");
                assert!(
                    segment
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '/' | '*' | '-')),
                    "{capability}: segment {segment:?} has a character outside the grammar"
                );
            }
        }
    }

    #[test]
    fn an_action_displays_its_capability() {
        assert_eq!(PlatformAction::OpenUrl.to_string(), "platform:open-url");
    }

    // ── URLs ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_https_url_is_accepted_by_default() {
        let policies = Policies::new();
        for url in [
            "https://example.com",
            "https://example.com/path?q=1#frag",
            "https://api.github.com/repos/synra-rs/synra-core",
            "https://example.com:8443/x",
        ] {
            assert_eq!(check_url(url, &policies), Ok(()), "{url}");
        }
    }

    #[test]
    fn a_plain_http_url_is_refused_by_default() {
        // The consent prompt shows the user a hostname. Over HTTP that hostname can be rewritten before the
        // response, so the prompt is true about the destination and false about what will be displayed.
        let policies = Policies::new();
        match check_url("http://example.com", &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::Insecure),
            other => panic!("expected an insecure refusal, got {other:?}"),
        }
        // And the refusal explains why, in terms of what the user is deciding about.
        assert!(UrlRefusal::Insecure.explain().contains("changed in transit"));
    }

    #[test]
    fn http_can_be_allowed_by_policy() {
        let policies = Policies::new().with_insecure_urls(true);
        assert_eq!(check_url("http://example.com", &policies), Ok(()));
    }

    #[rstest]
    #[case("javascript:alert(1)")]
    #[case("data:text/html,<script>x</script>")]
    #[case("vbscript:x")]
    #[case("file:///etc/passwd")]
    #[case("ftp://example.com")]
    fn a_non_web_scheme_is_refused_by_default(#[case] url: &str) {
        // The list is closed rather than "anything that is not http": each of these is something a plugin could
        // put behind an "open this link" prompt, and a `file:` URL reaches a path without passing through the
        // executable check.
        let policies = Policies::new();
        match check_url(url, &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::LocalScheme, "{url}"),
            other => panic!("{url} should be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_local_scheme_can_be_allowed_by_policy() {
        let policies = Policies::new().with_local_schemes(true);
        assert_eq!(check_url("file:///tmp/x", &policies), Ok(()));
    }

    #[test]
    fn a_url_with_no_scheme_or_host_is_refused() {
        let policies = Policies::new();
        for (url, expected) in [
            ("example.com", UrlRefusal::NoScheme),
            ("https://", UrlRefusal::NoHost),
            ("https:///path", UrlRefusal::NoHost),
            ("https://?q=1", UrlRefusal::NoHost),
            ("", UrlRefusal::Empty),
        ] {
            match check_url(url, &policies) {
                Err(PlatformError::BadUrl { reason, .. }) => {
                    assert_eq!(reason, expected, "{url:?}");
                }
                other => panic!("{url:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_control_character_in_a_url_is_refused() {
        // A newline could forge a line in the consent prompt or split a log record, and the prompt is what the user
        // decides from.
        let policies = Policies::new();
        for url in [
            "https://example.com/\nhttps://evil.com",
            "https://example.com/\u{7}",
            "https://exa\u{0}mple.com",
        ] {
            match check_url(url, &policies) {
                Err(PlatformError::BadUrl { reason, .. }) => {
                    assert_eq!(reason, UrlRefusal::ControlCharacter, "{url:?}");
                }
                other => panic!("{url:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_over_long_url_is_refused() {
        let policies = Policies::new();
        let long = format!("https://example.com/{}", "x".repeat(MAX_URL_LEN));
        match check_url(&long, &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::TooLong),
            other => panic!("expected a length refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_scheme_check_is_case_insensitive() {
        // `HTTPS://example.com` is the same scheme, and a comparison that missed it would refuse a legitimate
        // address.
        let policies = Policies::new();
        assert_eq!(check_url("HTTPS://example.com", &policies), Ok(()));
        assert!(check_url("HTTP://example.com", &policies).is_err());
    }

    #[test]
    fn every_url_refusal_explains_itself() {
        for reason in [
            UrlRefusal::Empty,
            UrlRefusal::TooLong,
            UrlRefusal::NoScheme,
            UrlRefusal::LocalScheme,
            UrlRefusal::Insecure,
            UrlRefusal::NoHost,
            UrlRefusal::ControlCharacter,
        ] {
            assert!(reason.explain().len() > 15, "{reason:?}");
        }
    }

    #[test]
    fn the_url_length_helper_refuses_before_the_open() {
        // So a caller building a URL finds out where it made the mistake rather than at the point a browser is
        // asked to open something.
        assert!(check_url_length("https://example.com").is_ok());
        let long = "x".repeat(MAX_URL_LEN + 1);
        assert!(matches!(
            check_url_length(&long),
            Err(PlatformError::TooLong { field: "address", .. })
        ));
    }

    // ── Paths ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_executable_extension_is_refused_for_opening() {
        // Opened with the default application, an executable runs.
        let policies = Policies::new();
        let root = sandbox_root();
        for extension in ["exe", "sh", "bat", "cmd", "ps1", "app", "dmg", "deb", "jar", "lnk"] {
            let path = absolute(&format!("thing.{extension}"));
            match check_path(&path, PathUse::Open, &policies, Some(root.as_path())) {
                Err(PlatformError::BadPath { reason, .. }) => {
                    assert_eq!(reason, PathRefusal::Executable, "{extension}");
                }
                other => panic!(".{extension} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_extension_check_ignores_case() {
        let policies = Policies::new();
        for extension in ["EXE", "Exe", "eXe"] {
            let path = absolute(&format!("thing.{extension}"));
            assert!(matches!(
                check_path(&path, PathUse::Open, &policies, None),
                Err(PlatformError::BadPath { reason: PathRefusal::Executable, .. })
            ));
        }
    }

    #[test]
    fn a_path_with_no_extension_is_refused_for_opening() {
        // The check's purpose is to prove a file is not a program, and with no extension there is nothing to prove
        // it with. A file named `invoice` with no extension could be anything.
        let policies = Policies::new();
        match check_path(absolute("invoice").as_path(), PathUse::Open, &policies, None) {
            Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::UnknownKind),
            other => panic!("expected an unknown-kind refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_document_may_be_opened() {
        let policies = Policies::new();
        for path in [absolute_text("report.pdf").as_str(), absolute_text("notes.txt").as_str(), absolute_text("image.png").as_str(), absolute_text("data.json").as_str()] {
            assert_eq!(
                check_path(Path::new(path), PathUse::Open, &policies, None),
                Ok(()),
                "{path}"
            );
        }
    }

    #[test]
    fn revealing_may_show_an_executable() {
        // Revealing selects a file in the file manager and runs nothing, so the extension check does not apply —
        // and applying it would refuse a legitimate "show me where my download went".
        let policies = Policies::new();
        let root = sandbox_root();
        let path = sandbox_root().join("files/setup.exe");
        let path = path.as_path();
        assert_eq!(check_path(path, PathUse::Reveal, &policies, Some(root.as_path())), Ok(()));
    }

    #[test]
    fn revealing_outside_the_sandbox_is_refused_by_default() {
        // Revealing an arbitrary path tells the plugin what exists on the disk, which is information it was not
        // given.
        let policies = Policies::new();
        match check_path(Path::new(absolute_text("passwd").as_str()), PathUse::Reveal, &policies, Some(sandbox_root().as_path())) {
            Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::OutsideSandbox),
            other => panic!("expected a sandbox refusal, got {other:?}"),
        }
    }

    #[test]
    fn revealing_with_no_sandbox_is_refused_when_the_policy_restricts() {
        // A check that cannot be made is not a check that passed.
        let policies = Policies::new();
        assert!(matches!(
            check_path(absolute("x.txt").as_path(), PathUse::Reveal, &policies, None),
            Err(PlatformError::BadPath { reason: PathRefusal::OutsideSandbox, .. })
        ));
    }

    #[test]
    fn the_sandbox_check_is_component_wise() {
        // `/sandbox` is a string prefix of `/sandbox-other`, so a string comparison would accept a sibling.
        let policies = Policies::new();
        let inside = sandbox_root().join("files/x.txt");
        let sibling = sibling_root().join("x.txt");

        assert!(
            check_path(inside.as_path(), PathUse::Reveal, &policies, Some(sandbox_root().as_path()))
                .is_ok()
        );
        assert!(
            check_path(sibling.as_path(), PathUse::Reveal, &policies, Some(sandbox_root().as_path()))
                .is_err()
        );
    }

    #[test]
    fn revealing_outside_the_sandbox_can_be_allowed_by_policy() {
        let policies = Policies::new().with_reveal_outside_sandbox(true);
        assert_eq!(
            check_path(absolute("x.txt").as_path(), PathUse::Reveal, &policies, None),
            Ok(())
        );
    }

    #[test]
    fn a_relative_path_is_refused() {
        // It would be checked against the working directory, which is whichever thread the host happened to be on,
        // so the same call would open different files at different times.
        let policies = Policies::new();
        for path in ["report.pdf", "./report.pdf", "a/b.txt"] {
            match check_path(Path::new(path), PathUse::Open, &policies, None) {
                Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::NotAbsolute, "{path}"),
                other => panic!("{path:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_empty_path_is_refused() {
        let policies = Policies::new();
        assert!(matches!(
            check_path(Path::new(""), PathUse::Open, &policies, None),
            Err(PlatformError::BadPath { reason: PathRefusal::Empty, .. })
        ));
    }

    #[test]
    fn every_path_refusal_explains_itself() {
        for reason in [
            PathRefusal::Empty,
            PathRefusal::NotAbsolute,
            PathRefusal::UnknownKind,
            PathRefusal::Executable,
            PathRefusal::OutsideSandbox,
            PathRefusal::ControlCharacter,
        ] {
            assert!(reason.explain().len() > 15, "{reason:?}");
        }
    }

    #[test]
    fn the_executable_list_covers_the_installation_formats() {
        // A list that missed one would be a list that lets that one through, and the failure is silent.
        for extension in ["exe", "msi", "dmg", "pkg", "deb", "rpm", "appimage", "apk"] {
            assert!(EXECUTABLE_EXTENSIONS.contains(&extension), "{extension} is not listed");
        }
        // And the entries are lowercase and without dots, which is what the comparison produces.
        for extension in EXECUTABLE_EXTENSIONS {
            assert_eq!(*extension, extension.to_ascii_lowercase(), "{extension}");
            assert!(!extension.starts_with('.'), "{extension}");
        }
    }

    // ── Notification and chord limits ─────────────────────────────────────────────────────────────

    #[test]
    fn a_notification_within_its_limits_is_accepted() {
        assert_eq!(check_notification("Synra", "A file arrived"), Ok(()));
        assert_eq!(check_notification("", ""), Ok(()));
    }

    #[test]
    fn an_over_long_notification_is_refused_and_names_the_field() {
        let long = "x".repeat(MAX_NOTIFICATION_LEN + 1);
        match check_notification(&long, "body") {
            Err(PlatformError::TooLong { field, len, max }) => {
                assert_eq!(field, "notification title");
                assert_eq!(len, MAX_NOTIFICATION_LEN + 1);
                assert_eq!(max, MAX_NOTIFICATION_LEN);
            }
            other => panic!("expected a length refusal, got {other:?}"),
        }
        assert!(matches!(
            check_notification("title", &long),
            Err(PlatformError::TooLong { field: "notification body", .. })
        ));
    }

    #[test]
    fn a_notification_is_measured_in_characters() {
        // A CJK notification of the same character count is not "too long" in a unit a user cannot see.
        let cjk = "电".repeat(MAX_NOTIFICATION_LEN);
        assert_eq!(check_notification(&cjk, &cjk), Ok(()));
    }

    #[test]
    fn an_empty_key_chord_is_refused() {
        // Not "no keys": a call that does nothing, and a loop of them would still hold the rate limiter.
        assert!(matches!(
            check_key_chord("   "),
            Err(PlatformError::Unavailable(_))
        ));
        assert_eq!(check_key_chord("cmd+c"), Ok(()));
        assert!(matches!(
            check_key_chord(&"x".repeat(MAX_CHORD_LEN + 1)),
            Err(PlatformError::TooLong { field: "key chord", .. })
        ));
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────────────────────────

    /// A limiter with a short interval so the arithmetic is easy to read.
    fn limiter() -> RateLimiter {
        RateLimiter::new(
            Policies::new()
                .with_key_chord_interval(Duration::from_millis(100))
                .with_notification_interval(Duration::from_millis(1_000))
                .with_notifications_per_hour(3),
        )
    }

    #[test]
    fn unrelated_actions_are_not_rate_limited() {
        // A rate limit on `open-url` would refuse a legitimate burst of links a user clicked.
        let limiter = limiter();
        for _ in 0..100 {
            assert_eq!(limiter.admit(PlatformAction::OpenUrl, 0), Ok(()));
            assert_eq!(limiter.admit(PlatformAction::ReadClipboard, 0), Ok(()));
        }
    }

    #[test]
    fn key_chords_are_spaced_out() {
        let limiter = limiter();
        assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 0), Ok(()));

        match limiter.admit(PlatformAction::SimulateKeys, 50) {
            Err(PlatformError::RateLimited { action, remaining_ms }) => {
                assert_eq!(action, PlatformAction::SimulateKeys);
                assert_eq!(remaining_ms, 50, "the wait is the remainder, not the whole interval");
            }
            other => panic!("expected a rate limit, got {other:?}"),
        }
        // At the interval it is allowed again.
        assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 100), Ok(()));
        assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 200), Ok(()));
    }

    #[test]
    fn notifications_are_spaced_out() {
        let limiter = limiter();
        assert_eq!(limiter.admit(PlatformAction::Notify, 0), Ok(()));
        assert!(matches!(
            limiter.admit(PlatformAction::Notify, 500),
            Err(PlatformError::RateLimited { .. })
        ));
        assert_eq!(limiter.admit(PlatformAction::Notify, 1_000), Ok(()));
    }

    #[test]
    fn an_hourly_ceiling_applies_to_notifications() {
        // An application that notifies more often than this is one whose notifications get turned off entirely.
        let limiter = limiter();
        // Spaced far enough apart to clear the interval, but only three are allowed in the window.
        for index in 0..3u64 {
            assert_eq!(
                limiter.admit(PlatformAction::Notify, index * 1_000),
                Ok(()),
                "notification {index}"
            );
        }
        match limiter.admit(PlatformAction::Notify, 3_000) {
            Err(PlatformError::QuotaExceeded { action, used, limit }) => {
                assert_eq!(action, PlatformAction::Notify);
                assert_eq!(used, 3);
                assert_eq!(limit, 3);
            }
            other => panic!("expected a quota refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_notification_window_slides() {
        // A fixed window would let a plugin fire the whole ceiling at the end of one hour and again at the start
        // of the next.
        let limiter = limiter();
        for index in 0..3u64 {
            limiter.admit(PlatformAction::Notify, index * 1_000).expect("within the ceiling");
        }
        assert_eq!(limiter.notifications_in_window(3_000), 3);

        // An hour after the first, that one has left the window.
        let later = 3_600_000 + 1;
        assert_eq!(limiter.notifications_in_window(later), 2);
        // So a fourth is allowed at that point.
        assert!(limiter.admit(PlatformAction::Notify, later).is_ok());
    }

    #[test]
    fn forgetting_an_action_clears_its_history() {
        // A device resuming from suspend has a clock that did not advance, and the alternative to forgetting is a
        // plugin that cannot notify until the process restarts.
        let limiter = limiter();
        limiter.admit(PlatformAction::Notify, 0).expect("first");
        assert!(limiter.admit(PlatformAction::Notify, 0).is_err());

        limiter.forget(PlatformAction::Notify);
        assert_eq!(limiter.notifications_in_window(0), 0);
        assert!(limiter.admit(PlatformAction::Notify, 0).is_ok());
    }

    #[test]
    fn a_zero_interval_allows_every_call() {
        // A configuration that disables the limit must actually disable it, not turn it into a refusal.
        let limiter = RateLimiter::new(
            Policies::new()
                .with_key_chord_interval(Duration::ZERO)
                .with_notification_interval(Duration::ZERO)
                .with_notifications_per_hour(1_000),
        );
        for _ in 0..5 {
            assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 0), Ok(()));
            assert_eq!(limiter.admit(PlatformAction::Notify, 0), Ok(()));
        }
    }

    // ── Policies ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_defaults_are_the_restrictive_ones() {
        // A host that wants to be permissive has to say so, which is the opposite of a configuration whose
        // defaults quietly allow whatever was added last.
        let policies = Policies::new();
        assert!(!policies.allows_insecure_urls());
        assert!(!policies.allows_simulate_keys());
        assert!(policies.restricts_reveal_to_sandbox());
        assert_eq!(policies.notifications_per_hour(), 20);
        assert!(policies.foreground_window() > Duration::ZERO);
        assert!(policies.key_chord_interval() > Duration::ZERO);
        assert!(policies.notification_interval() > Duration::ZERO);
    }

    #[test]
    fn a_policy_describes_what_a_grant_would_allow() {
        // Composed from the policy rather than written per action, so a policy change cannot leave the prompt
        // describing something the host no longer does.
        let strict = Policies::new();
        let open = Policies::new()
            .with_insecure_urls(true)
            .with_simulate_keys(true)
            .with_reveal_outside_sandbox(true);

        assert!(strict.describe(PlatformAction::OpenUrl).contains("https"));
        assert!(!open.describe(PlatformAction::OpenUrl).contains("https only"));

        assert!(strict.describe(PlatformAction::SimulateKeys).contains("turned off"));
        assert!(!open.describe(PlatformAction::SimulateKeys).contains("turned off"));

        assert!(strict.describe(PlatformAction::RevealPath).contains("own data directory"));
        assert!(!open.describe(PlatformAction::RevealPath).contains("own data directory"));

        // Every action has a description under both policies, so the screen has something to render.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            assert!(!strict.describe(action).is_empty(), "{action}");
            assert!(!open.describe(action).is_empty(), "{action}");
        }
    }

    #[test]
    fn the_builders_are_chainable() {
        let policies = Policies::new()
            .with_insecure_urls(true)
            .with_local_schemes(true)
            .with_simulate_keys(true)
            .with_foreground_requirement(false)
            .with_foreground_window(Duration::from_secs(5))
            .with_key_chord_interval(Duration::from_millis(10))
            .with_notification_interval(Duration::from_secs(1))
            .with_notifications_per_hour(5)
            .with_reveal_outside_sandbox(true);

        assert!(policies.allows_insecure_urls());
        assert!(policies.allows_simulate_keys());
        assert!(!policies.restricts_reveal_to_sandbox());
        assert_eq!(policies.foreground_window(), Duration::from_secs(5));
        assert_eq!(policies.key_chord_interval(), Duration::from_millis(10));
        assert_eq!(policies.notifications_per_hour(), 5);
    }

    // ── The headless host ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_headless_host_performs_nothing() {
        // Every action reports `Unsupported` rather than pretending to succeed, so a caller that forgot to provide
        // a real implementation finds out immediately.
        let host = HeadlessPlatform::new();
        assert_eq!(host.name(), "headless");
        assert!(matches!(host.open_url("https://example.com"), Err(PlatformError::Unsupported(_))));
        assert!(matches!(host.read_clipboard(), Err(PlatformError::Unsupported(_))));
        assert!(matches!(host.write_clipboard("x"), Err(PlatformError::Unsupported(_))));
        assert!(matches!(host.notify("t", "b"), Err(PlatformError::Unsupported(_))));
        // Key simulation is refused for a second reason before the host is consulted: it is off by default, and
        // that refusal is about the policy rather than about the host having no keyboard.
        assert!(matches!(
            host.simulate_keys("cmd+c"),
            Err(PlatformError::SimulateKeysNotGranted)
        ));
        // With the policy in place it reaches the host, which then refuses.
        let granted = HeadlessPlatform::with_policies(Policies::new().with_simulate_keys(true));
        assert!(matches!(
            granted.simulate_keys("cmd+c"),
            Err(PlatformError::Unsupported(_))
        ));
        assert!(host.supported_actions().is_empty());
    }

    #[test]
    fn a_headless_host_still_reports_a_bad_address() {
        // The order matters: a plugin that supplied `javascript:` should be told its address is refused, not that
        // this host has no browser. The first is a mistake the author can fix and the second is a fact about the
        // installation.
        let host = HeadlessPlatform::new();
        match host.open_url("javascript:alert(1)") {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::LocalScheme),
            other => panic!("expected a URL refusal, got {other:?}"),
        }
        match host.open_url("http://example.com") {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::Insecure),
            other => panic!("expected an insecure refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_headless_host_uses_the_policies_it_was_given() {
        let host = HeadlessPlatform::with_policies(Policies::new().with_insecure_urls(true));
        assert!(host.policies().allows_insecure_urls());
        // Still unsupported, but the address check passed, so the error is about the host.
        assert!(matches!(host.open_url("http://example.com"), Err(PlatformError::Unsupported(_))));
    }

    #[test]
    fn the_headless_host_checks_paths_before_refusing() {
        let host = HeadlessPlatform::new();
        // A relative path is refused for being relative, not for the host being headless.
        match host.open_path(Path::new("report.pdf")) {
            Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::NotAbsolute),
            other => panic!("expected a path refusal, got {other:?}"),
        }
        // And an absolute document reaches the host, which then refuses. The path is bound rather than passed as a
        // temporary, because `as_path` borrows it.
        let document = absolute("report.pdf");
        match host.open_path(document.as_path()) {
            Err(PlatformError::Unsupported(_)) => {}
            other => panic!("expected the host to refuse {document:?}, got {other:?}"),
        }
    }

    #[test]
    fn platform_errors_explain_themselves() {
        let errors = vec![
            PlatformError::BadUrl { url: "u".to_owned(), reason: UrlRefusal::Insecure },
            PlatformError::BadPath { path: "p".to_owned(), reason: PathRefusal::Executable },
            PlatformError::SimulateKeysNotGranted,
            PlatformError::NoRecentInteraction { elapsed_ms: 5_000 },
            PlatformError::RateLimited { action: PlatformAction::Notify, remaining_ms: 10 },
            PlatformError::QuotaExceeded { action: PlatformAction::Notify, used: 3, limit: 3 },
            PlatformError::TooLong { field: "f", len: 1, max: 0 },
            PlatformError::Unavailable("do a thing"),
            PlatformError::Unsupported("do a thing"),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// The same platform-absolute fixture the unit tests use, so a path is absolute on the platform running the
    /// test rather than under the one the literal was written for.
    fn absolute(name: &str) -> std::path::PathBuf {
        let base = if cfg!(windows) { "C:\\tmp" } else { "/tmp" };
        Path::new(base).join(name)
    }

    /// A plugin's sandbox root.
    fn sandbox_root() -> std::path::PathBuf {
        absolute("sandbox")
    }

    proptest! {
        /// A URL that passes the check is one the host will actually open, so it is either https or a scheme the
        /// policy explicitly allowed. The property is what stops a refusal from being bypassed by an unusual
        /// spelling.
        #[test]
        fn an_accepted_url_has_an_allowed_scheme(
            scheme in "[a-zA-Z]{2,8}",
            host in "[a-z]{1,10}\\.[a-z]{2,4}",
            path in proptest::option::of("/[a-z/]{0,10}"),
        ) {
            let url = format!("{scheme}://{host}{}", path.unwrap_or_default());
            let strict = Policies::new();
            let permissive = Policies::new().with_insecure_urls(true).with_local_schemes(true);

            for policies in [&strict, &permissive] {
                if check_url(&url, policies).is_ok() {
                    let lowered = scheme.to_ascii_lowercase();
                    let acceptable = lowered == "https"
                        || (lowered == "http" && policies.allows_insecure_urls())
                        || policies.allows_insecure_urls() && policies.allows_local_schemes();
                    prop_assert!(acceptable, "{} was accepted with scheme {}", url, scheme);
                }
            }
        }

        /// Whatever the input, checking a URL is total. A URL a plugin supplies is untrusted text, and the check
        /// runs before anything else sees it.
        #[test]
        fn checking_a_url_is_total(url in ".{0,200}") {
            let policies = Policies::new();
            let _ = check_url(&url, &policies);
            let _ = check_url_length(&url);
        }

        /// A path is refused for opening whenever its extension is an executable one, however the extension is
        /// spelled. Case folding is where such a check usually fails.
        #[test]
        fn an_executable_extension_is_always_refused(
            stem in "[a-z]{1,8}",
            index in 0usize..EXECUTABLE_EXTENSIONS.len(),
            upper in any::<bool>(),
        ) {
            let extension = EXECUTABLE_EXTENSIONS[index];
            let extension = if upper { extension.to_ascii_uppercase() } else { extension.to_owned() };
            let path = absolute(&format!("{stem}.{extension}"));

            let result = check_path(&path, PathUse::Open, &Policies::new(), None);
            prop_assert!(
                matches!(result, Err(PlatformError::BadPath { reason: PathRefusal::Executable, .. })),
                "{:?} -> {:?}",
                path,
                result,
            );
        }

        /// Checking a path is total, whatever the text. Paths come from plugins and from messages.
        #[test]
        fn checking_a_path_is_total(text in ".{0,120}") {
            let policies = Policies::new();
            let path = Path::new(&text);
            let _ = check_path(path, PathUse::Open, &policies, None);
            let root = sandbox_root();
            let _ = check_path(path, PathUse::Reveal, &policies, Some(root.as_path()));
        }

        /// The rate limiter never admits two key chords closer together than the interval, whatever the times
        /// supplied. It is the property that bounds how fast a plugin can type into another application.
        #[test]
        fn key_chords_respect_their_interval(
            interval_ms in 1u64..500,
            times in proptest::collection::vec(0u64..2_000, 0..40),
        ) {
            let limiter = RateLimiter::new(
                Policies::new().with_key_chord_interval(Duration::from_millis(interval_ms)),
            );
            let mut last_admitted: Option<u64> = None;
            for at in times {
                if limiter.admit(PlatformAction::SimulateKeys, at).is_ok() {
                    if let Some(previous) = last_admitted {
                        // Time may go backwards if the caller supplies unsorted times, and the limiter treats that
                        // as no elapsed time.
                        prop_assert!(
                            at.saturating_sub(previous) >= interval_ms || at < previous,
                            "admitted {} after {} with a {}-ms interval",
                            at,
                            previous,
                            interval_ms,
                        );
                    }
                    last_admitted = Some(at);
                }
            }
        }
    }
}
