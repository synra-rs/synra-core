//! How verbose the process is, and the clock that decides when it lapses.

use std::sync::Arc;

use super::level::LogLevel;
use parking_lot::Mutex;

/// How long a temporary verbosity increase lasts.
///
/// Thirty minutes, because that is long enough to reproduce a problem and short enough that a forgotten
/// switch does not leave a device writing debug logs for a month.
pub const VERBOSE_WINDOW: core::time::Duration = core::time::Duration::from_secs(30 * 60);

/// The runtime verbosity, with an expiring override.
///
/// Two levels: the configured one, and a temporary one that a user turns on from the diagnostics screen.
/// The override needs no timer to expire — [`Self::effective`] checks the deadline, so a device that was
/// suspended through the whole window comes back with normal logging rather than a stale override.
#[derive(Debug)]
pub struct Verbosity {
    /// What the configuration says.
    configured: LogLevel,
    /// The temporary level, if one is active.
    override_level: Mutex<Option<(LogLevel, std::time::Instant)>>,
    /// Injected clock reading, so a test can move time without sleeping.
    now: Clock,
}

/// A clock reading, wrapped so it can be `Debug`.
///
/// A closure has no useful representation, and the alternative — hand-writing `Debug` for [`Verbosity`]
/// — means every field added later has to be added there too, which is how a field ends up missing from
/// the output.
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> std::time::Instant + Send + Sync>);

impl Clock {
    /// Reads the clock.
    fn now(&self) -> std::time::Instant {
        (self.0)()
    }
}

impl core::fmt::Debug for Clock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<clock>")
    }
}

impl Verbosity {
    /// Builds a verbosity with the given configured level.
    #[must_use]
    pub fn new(configured: LogLevel) -> Self {
        Self {
            configured,
            override_level: Mutex::new(None),
            now: Clock(Arc::new(std::time::Instant::now)),
        }
    }

    /// Builds a verbosity whose clock is supplied, for tests.
    #[must_use]
    pub fn with_clock(
        configured: LogLevel,
        now: impl Fn() -> std::time::Instant + Send + Sync + 'static,
    ) -> Self {
        Self { configured, override_level: Mutex::new(None), now: Clock(Arc::new(now)) }
    }

    /// The configured level.
    #[must_use]
    pub const fn configured(&self) -> LogLevel {
        self.configured
    }

    /// The level in force right now.
    #[must_use]
    pub fn effective(&self) -> LogLevel {
        let now = self.now.now();
        let guard = self.override_level.lock();
        match *guard {
            Some((level, until)) if now < until => level,
            // Expired. The entry is left in place rather than cleared here, because `effective` is called
            // on every log line and taking a write lock on the hot path is what a read-mostly structure
            // is meant to avoid.
            Some(_) => self.configured,
            None => self.configured,
        }
    }

    /// Raises verbosity to `level` for [`VERBOSE_WINDOW`].
    pub fn raise_for_a_while(&self, level: LogLevel) {
        let until = self.now.now() + VERBOSE_WINDOW;
        *self.override_level.lock() = Some((level, until));
    }

    /// Raises verbosity until `until`.
    ///
    /// For a caller that already has a deadline — the settings screen showing a countdown, for instance.
    pub fn raise_until(&self, level: LogLevel, until: std::time::Instant) {
        *self.override_level.lock() = Some((level, until));
    }

    /// Ends a temporary increase immediately.
    pub fn reset(&self) {
        *self.override_level.lock() = None;
    }

    /// Whether a temporary increase is active.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        let now = self.now.now();
        self.override_level
            .lock()
            .is_some_and(|(_, until)| now < until)
    }

    /// How long the temporary increase has left.
    #[must_use]
    pub fn remaining(&self) -> Option<core::time::Duration> {
        let now = self.now.now();
        self.override_level.lock().as_ref().and_then(|(_, until)| {
            until.checked_duration_since(now)
        })
    }
}
