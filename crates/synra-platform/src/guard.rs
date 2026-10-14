//! The checks, and the rate limiter that decides whether an action may proceed.
//!
//! # Why the clock is an argument
//!
//! Because the limits must be testable without sleeping. `RateLimiter` answers "may this happen now" and records the
//! answer; the caller supplies `now_ms`. A limiter that read the wall clock would make every test of a limit a test
//! that takes as long as the limit.

use std::path::Path;

use super::actions::{
    Policies, PlatformAction, EXECUTABLE_EXTENSIONS, MAX_CHORD_LEN, MAX_NOTIFICATION_LEN, MAX_URL_LEN,
};
use super::error::{PathRefusal, PlatformError, UrlRefusal};

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
