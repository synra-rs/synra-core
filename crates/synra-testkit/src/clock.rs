//! The clock, and a mock one that does not sleep.
//!
//! # Why the kernel takes a clock rather than reading one
//!
//! Every timing decision in the kernel — a handshake timeout, a heartbeat, a backoff, a transfer's idle sweep — is
//! a decision about *when*, and a correctness test for one of them has two options:
//!
//! * Sleep for the real interval and hope the assertion is not flaky on a loaded machine.
//! * Move the clock and assert exactly.
//!
//! The first is why timing bugs survive test suites. A test that sleeps six seconds for a handshake timeout is one
//! nobody writes, and the ones that get written assert `>=` rather than `==` — which passes for a timeout that fires
//! at ten times the intended moment.
//!
//! So the kernel asks a [`Clock`] and the test supplies [`MockClock`]. The same code path runs; only the source of
//! "now" differs.
//!
//! # The mock is not a scheduler
//!
//! It has no queues and runs nothing. Advancing it moves the reading forward and reports what became due, so a test
//! decides what to do about it — which keeps the mock from growing into a second implementation of the kernel's
//! scheduling, with its own bugs.
//!
//! # Monotonic, and why that is not window dressing
//!
//! A wall clock can move backwards: an NTP correction, a user changing the time, a device resuming from suspend. A
//! timeout computed from a wall clock can therefore be *negative*, and code that then waits "until the deadline"
//! waits forever. The kernel's clock is monotonic — it only ever moves forward — and the mock is too, which is what
//! makes a test of that property possible at all.

use core::time::Duration;

/// A source of monotonic time.
///
/// Synchronous, because reading a monotonic clock is a register read: an `async fn now()` would make every caller
/// await something that never yields, and every timing decision `async` for no reason.
pub trait Clock: Send + Sync {
    /// Milliseconds since this clock's origin.
    ///
    /// Deliberately not "milliseconds since the epoch". The origin is the process's start for a monotonic clock, so
    /// comparing two readings is meaningful and comparing a reading to a wall-clock timestamp is not — which is a
    /// mistake the type can prevent by not exposing one.
    fn now_ms(&self) -> u64;

    /// The current reading, as a duration since the origin.
    fn now(&self) -> Duration {
        Duration::from_millis(self.now_ms())
    }
}

/// A clock that reads the real, monotonic time.
///
/// The origin is the first reading this process took, so `now_ms` starts near zero rather than near the number of
/// milliseconds since 1970 — which keeps it well inside the range an `f64` can represent exactly, for the places a
/// duration ends up in JSON.
#[derive(Debug)]
pub struct SystemClock {
    origin: std::time::Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self { origin: std::time::Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // Saturating because a process that has run for six hundred million years is not the problem worth a panic.
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Why a clock advance was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClockError {
    /// The mock was asked to move backwards.
    #[error("a monotonic clock cannot go from {from}ms to {to}ms")]
    Backwards {
        /// Where it was.
        from: u64,
        /// Where it was asked to go.
        to: u64,
    },

    /// The mock would wrap.
    #[error("advancing by {by}ms from {from}ms would overflow")]
    Overflow {
        /// Where it was.
        from: u64,
        /// How far it was asked to move.
        by: u64,
    },

    /// Advancing would run past the deadline the test set.
    ///
    /// A guard rather than a feature: a test that advances past its own deadline is usually a test that has lost
    /// track of what it is asserting, and the failure is clearer here than as an assertion three steps later.
    #[error("advancing to {to}ms would pass the {limit}ms the test set as its limit")]
    PastTheLimit {
        /// Where it was asked to go.
        to: u64,
        /// The limit.
        limit: u64,
    },
}

/// A clock the test moves.
///
/// Shared between the code under test and the test itself, so advancing it is visible to both.
#[derive(Debug)]
pub struct MockClock {
    now: parking_lot::Mutex<u64>,
    /// A guard against a test running past its own deadline, when it set one.
    limit: parking_lot::Mutex<Option<u64>>,
    /// When a deadline is set, this is how many times the clock was read — for a test asserting that a poll loop
    /// actually polled rather than spinning.
    reads: parking_lot::Mutex<u64>,
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MockClock {
    #[allow(clippy::missing_const_for_fn)]
    /// A clock at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: parking_lot::Mutex::new(0),
            limit: parking_lot::Mutex::new(None),
            reads: parking_lot::Mutex::new(0),
        }
    }

    /// A clock at a starting reading.
    ///
    /// For a test that wants to start somewhere other than the origin, such as one about a persisted timestamp.
    #[must_use]
    pub fn starting_at(ms: u64) -> Self {
        Self { now: parking_lot::Mutex::new(ms), ..Self::new() }
    }

    /// Moves the clock forward.
    ///
    /// # Errors
    ///
    /// [`ClockError`] if the move would overflow, or if a limit was set and this passes it.
    pub fn advance(&self, by: Duration) -> Result<u64, ClockError> {
        let by_ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        let current = *self.now.lock();
        let Some(next) = current.checked_add(by_ms) else {
            return Err(ClockError::Overflow { from: current, by: by_ms });
        };
        self.move_to(next)
    }

    /// Moves the clock to a reading.
    ///
    /// # Errors
    ///
    /// [`ClockError::Backwards`] if the reading is in the past, or [`ClockError::PastTheLimit`] if a limit was set.
    pub fn move_to(&self, to: u64) -> Result<u64, ClockError> {
        let current = *self.now.lock();
        if to < current {
            return Err(ClockError::Backwards { from: current, to });
        }
        if let Some(limit) = *self.limit.lock()
            && to > limit
        {
            return Err(ClockError::PastTheLimit { to, limit });
        }
        *self.now.lock() = to;
        Ok(to)
    }

    /// Sets a reading past which the test must not move.
    ///
    /// # Errors
    ///
    /// [`ClockError::Backwards`] if the limit is behind the current reading, which would make the next advance fail
    /// for a reason the test did not intend.
    pub fn set_limit(&self, limit: u64) -> Result<(), ClockError> {
        let current = *self.now.lock();
        if limit < current {
            return Err(ClockError::Backwards { from: current, to: limit });
        }
        *self.limit.lock() = Some(limit);
        Ok(())
    }

    /// Removes the limit.
    pub fn clear_limit(&self) {
        *self.limit.lock() = None;
    }

    /// How many times the clock has been read.
    ///
    /// For a test asserting that a poll loop polled rather than spinning on a cached reading.
    #[must_use]
    pub fn reads(&self) -> u64 {
        *self.reads.lock()
    }
}

impl Clock for MockClock {
    fn now_ms(&self) -> u64 {
        // One lock acquisition at a time. `*self.reads.lock() = self.reads.lock()...` takes the lock twice in one
        // expression, and `parking_lot`'s mutex is not reentrant: the second acquisition deadlocks, so this is the
        // difference between a counter and a hang on every read of the clock.
        {
            let mut reads = self.reads.lock();
            *reads = reads.saturating_add(1);
        }
        *self.now.lock()
    }
}

/// A deadline a test can assert against.
///
/// A small helper rather than a bare `Duration`, because the comparison a test wants is almost always "has this
/// passed" and writing it as `clock.now_ms() >= deadline.at_ms` at every site is where the off-by-one lives — a
/// deadline is due *at* its reading, not after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline {
    at_ms: u64,
}

impl Deadline {
    /// A deadline `after` from a reading.
    #[must_use]
    pub const fn after(now_ms: u64, after: Duration) -> Self {
        Self { at_ms: now_ms.saturating_add(after.as_millis() as u64) }
    }

    /// A deadline at an absolute reading.
    #[must_use]
    pub const fn at(at_ms: u64) -> Self {
        Self { at_ms }
    }

    /// The reading it falls due at.
    #[must_use]
    pub const fn at_ms(self) -> u64 {
        self.at_ms
    }

    /// Whether it is due at a reading.
    ///
    /// `>=`, because a deadline is due *at* its instant. A `>` here is the off-by-one that makes a timeout fire a
    /// millisecond late, which no test notices and which compounds in a chain of them.
    #[must_use]
    pub const fn is_due(self, now_ms: u64) -> bool {
        now_ms >= self.at_ms
    }

    /// How long is left, or zero once it is due.
    #[must_use]
    pub const fn remaining(self, now_ms: u64) -> Duration {
        Duration::from_millis(self.at_ms.saturating_sub(now_ms))
    }

    /// How long ago it fell due, or zero if it has not.
    #[must_use]
    pub const fn overdue_by(self, now_ms: u64) -> Duration {
        Duration::from_millis(now_ms.saturating_sub(self.at_ms))
    }
}

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
