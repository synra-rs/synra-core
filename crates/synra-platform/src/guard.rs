//! The checks, and the rate limiter that decides whether an action may proceed.
//!
//! # Why the clock is an argument
//!
//! Because the limits must be testable without sleeping. `RateLimiter` answers "may this happen now" and records the
//! answer; the caller supplies `now_ms`. A limiter that read the wall clock would make every test of a limit a test
//! that takes as long as the limit.

use std::path::{Component, Path};

use super::actions::{
    Policies, PlatformAction, EXECUTABLE_EXTENSIONS, MAX_CHORD_LEN, MAX_NOTIFICATION_LEN, MAX_URL_LEN,
};
use super::error::{PathRefusal, PlatformError, UrlRefusal};

/// Check the shared UTF-8 byte budget before writing clipboard text.
///
/// # Errors
/// [`PlatformError::TooLong`] when the encoded text exceeds [`crate::MAX_CLIPBOARD_BYTES`].
pub const fn check_clipboard_text(text: &str) -> Result<(), PlatformError> {
    if text.len() > crate::MAX_CLIPBOARD_BYTES {
        return Err(PlatformError::TooLong {
            field: "clipboard text in UTF-8 bytes",
            len: text.len(),
            max: crate::MAX_CLIPBOARD_BYTES,
        });
    }
    Ok(())
}

/// The Windows device names, without their extensions and in upper case.
///
/// # Why each of these is a device and not a file
///
/// Because Windows has reserved them since DOS and still resolves them **before** the file system: `NUL` is a sink that
/// discards whatever is written, `CON` is the console, `AUX` and `PRN` are the first serial and parallel ports, and
/// `COM1`–`COM9` and `LPT1`–`LPT9` are those ports by number. A sandbox that believed it had written
/// `<root>/NUL` would have written nothing at all, and one that believed it had read `<root>/CON` would be reading the
/// console — so the check is not about tidiness, it is about the kernel and the file system disagreeing on what a name
/// means.
const RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether one path component names a Windows device rather than a file.
///
/// # The three things Windows ignores, and why each is handled here
///
/// 1. **Case.** `nul`, `Nul` and `NUL` are the same device.
/// 2. **A trailing dot or space.** Windows strips them from a name before resolving it, so `NUL.` and `NUL ` are `NUL` —
///    and a check that compared the text as written would pass both.
/// 3. **The extension.** `CON.txt` is still the console, because the device is resolved before the extension is looked at.
///    This is the one that surprises people, and the reason the comparison is on the part before the first dot.
///
/// The check is applied on every platform rather than only on Windows, because a path is data: a kernel on Linux that
/// passes `NUL` through is one whose *behaviour* changes when the same plugin runs on Windows, and the capability model
/// is about what a plugin may do rather than about which machine it happens to be doing it on.
#[must_use]
pub fn is_reserved_name(component: &str) -> bool {
    let trimmed = component.trim_end_matches([' ', '.']);
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    // `eq_ignore_ascii_case` rather than `to_ascii_uppercase` into a `String`: this runs per component on every path a
    // plugin touches, and the comparison allocates nothing.
    RESERVED_NAMES.iter().any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// Whether a path begins in the Windows device namespace.
///
/// # Why these are refused rather than normalised
///
/// The design's table says to normalise them, and for the sandbox check that would be wrong. `\\?\` is not decoration: it
/// turns **off** the path cleaning Windows otherwise does, so `\\?\C:\data\..\..\Windows` is a literal name for a directory
/// called `..` rather than a way back up the tree. Two paths that look like each other therefore do not mean the same
/// thing, and a check that stripped the prefix and compared the rest would be comparing a name with a different one — and
/// the difference is exactly the part that decides where the data goes.
///
/// The same applies to `\\server\share`, which names a machine rather than a place inside this one: nothing under the
/// sandbox root can contain it, and treating it as a path to compare would be pretending otherwise.
#[must_use]
pub fn is_device_namespace(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if prefix.as_os_str().to_string_lossy().starts_with(r"\\")
    )
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

    // ★ The Windows traps, and why they are checked here rather than where the file is opened.
    //
    // Each of these makes the kernel's idea of a name differ from the file system's. A check made at the point of the open
    // would be a check that had already decided which of the two it was talking to.
    if is_device_namespace(path) {
        return Err(refuse(PathRefusal::DeviceNamespace));
    }
    for component in path.components() {
        let text = component.as_os_str().to_string_lossy();
        // ★ An alternate data stream: `notes.txt:secret` is a second, hidden stream of `notes.txt`, and `evil.exe:x` is a
        // stream of a program rather than the program. Windows allows it on NTFS, every other platform treats the colon as
        // an ordinary character in a name, and the two readings differ — so the path is refused rather than interpreted.
        //
        // The drive prefix is excluded because on Windows `C:` is a prefix and not a component of the path.
        if !matches!(component, Component::Prefix(_)) && text.contains(':') {
            return Err(refuse(PathRefusal::AlternativeStream));
        }
        if is_reserved_name(&text) {
            return Err(refuse(PathRefusal::ReservedName));
        }
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
