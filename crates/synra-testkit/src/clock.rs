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
mod tests {
    use super::*;

    #[test]
    fn a_mock_clock_starts_at_zero() {
        let clock = MockClock::new();
        assert_eq!(clock.now_ms(), 0);
        assert_eq!(clock.now(), Duration::ZERO);
    }

    #[test]
    fn advancing_moves_the_reading() {
        let clock = MockClock::new();
        assert_eq!(clock.advance(Duration::from_millis(250)), Ok(250));
        assert_eq!(clock.now_ms(), 250);
        assert_eq!(clock.advance(Duration::from_millis(750)), Ok(1_000));
        assert_eq!(clock.now_ms(), 1_000);
    }

    #[test]
    fn advancing_by_zero_is_allowed_and_changes_nothing() {
        // A caller that computed a delay of zero should not have to special-case it, and a test that wants to poll
        // without moving should be able to.
        let clock = MockClock::starting_at(100);
        assert_eq!(clock.advance(Duration::ZERO), Ok(100));
        assert_eq!(clock.now_ms(), 100);
    }

    #[test]
    fn the_clock_never_moves_backwards() {
        // A wall clock can move backwards — an NTP correction, a user changing the time — and a timeout computed
        // from one can then be negative, which is code that waits forever.
        let clock = MockClock::starting_at(500);
        match clock.move_to(400) {
            Err(ClockError::Backwards { from, to }) => {
                assert_eq!(from, 500);
                assert_eq!(to, 400);
            }
            other => panic!("expected a backwards refusal, got {other:?}"),
        }
        assert_eq!(clock.now_ms(), 500, "the reading moved anyway");
    }

    #[test]
    fn moving_to_the_same_reading_is_allowed() {
        let clock = MockClock::starting_at(500);
        assert_eq!(clock.move_to(500), Ok(500));
    }

    #[test]
    fn advancing_past_the_end_of_the_range_is_refused_rather_than_wrapping() {
        // A wrap would put the clock in the past, which is the one thing a monotonic clock exists to prevent.
        let clock = MockClock::starting_at(u64::MAX - 10);
        match clock.advance(Duration::from_millis(100)) {
            Err(ClockError::Overflow { from, by }) => {
                assert_eq!(from, u64::MAX - 10);
                assert_eq!(by, 100);
            }
            other => panic!("expected an overflow refusal, got {other:?}"),
        }
        assert_eq!(clock.now_ms(), u64::MAX - 10);
    }

    #[test]
    fn a_limit_stops_a_test_running_past_its_own_deadline() {
        // A test that advances past the deadline it meant to assert about is usually one that has lost track of what
        // it is checking, and failing here is clearer than an assertion three steps later.
        let clock = MockClock::new();
        clock.set_limit(1_000).expect("sets a limit");
        assert_eq!(clock.advance(Duration::from_millis(600)), Ok(600));
        match clock.advance(Duration::from_millis(600)) {
            Err(ClockError::PastTheLimit { to, limit }) => {
                assert_eq!(to, 1_200);
                assert_eq!(limit, 1_000);
            }
            other => panic!("expected a limit refusal, got {other:?}"),
        }
        assert_eq!(clock.now_ms(), 600, "the reading moved past the limit anyway");
    }

    #[test]
    fn the_limit_includes_the_instant_it_names() {
        // A test that sets a deadline of 1 000 ms and advances to exactly 1 000 is asserting about the deadline, not
        // running past it.
        let clock = MockClock::new();
        clock.set_limit(1_000).expect("sets a limit");
        assert_eq!(clock.move_to(1_000), Ok(1_000));
    }

    #[test]
    fn a_limit_behind_the_current_reading_is_refused() {
        // It would make the next advance fail for a reason the test did not intend.
        let clock = MockClock::starting_at(500);
        assert!(matches!(clock.set_limit(400), Err(ClockError::Backwards { .. })));
    }

    #[test]
    fn a_limit_can_be_cleared() {
        let clock = MockClock::new();
        clock.set_limit(100).expect("sets a limit");
        clock.clear_limit();
        assert_eq!(clock.advance(Duration::from_millis(1_000)), Ok(1_000));
    }

    #[test]
    fn the_clock_counts_its_reads() {
        // For a test asserting that a poll loop actually polled rather than spinning on a cached reading.
        let clock = MockClock::new();
        let _ = clock.now_ms();
        let _ = clock.now_ms();
        let _ = clock.now();
        assert_eq!(clock.reads(), 3);
    }

    #[test]
    fn a_deadline_is_due_at_its_instant_not_after_it() {
        // A `>` here is the off-by-one that makes a timeout fire a millisecond late, which no test notices and which
        // compounds in a chain of them.
        let deadline = Deadline::after(1_000, Duration::from_millis(500));
        assert_eq!(deadline.at_ms(), 1_500);
        assert!(!deadline.is_due(1_499));
        assert!(deadline.is_due(1_500), "a deadline is due at its instant");
        assert!(deadline.is_due(1_501));
    }

    #[test]
    fn a_deadline_reports_what_is_left_and_what_is_past() {
        let deadline = Deadline::at(1_000);
        assert_eq!(deadline.remaining(600), Duration::from_millis(400));
        assert_eq!(deadline.remaining(1_000), Duration::ZERO);
        assert_eq!(deadline.remaining(2_000), Duration::ZERO, "not negative");

        assert_eq!(deadline.overdue_by(600), Duration::ZERO);
        assert_eq!(deadline.overdue_by(1_000), Duration::ZERO);
        assert_eq!(deadline.overdue_by(1_400), Duration::from_millis(400));
    }

    #[test]
    fn a_deadline_that_would_overflow_saturates() {
        // A deadline computed from a reading near the end of the range is not a reason to panic.
        let deadline = Deadline::after(u64::MAX, Duration::from_secs(1));
        assert_eq!(deadline.at_ms(), u64::MAX);
        assert!(deadline.is_due(u64::MAX));
    }

    #[test]
    fn deadlines_order_by_their_instant() {
        // A test asserting that one timeout fires before another needs the ordering, and it is the reason the type
        // derives `Ord` rather than a caller comparing `at_ms` at each site.
        let early = Deadline::at(100);
        let late = Deadline::at(200);
        assert!(early < late);
        assert_eq!(early, Deadline::at(100));
    }

    #[test]
    fn the_system_clock_starts_near_zero_and_moves_forward() {
        // The origin is the first reading rather than 1970, which keeps the value well inside the range an `f64` can
        // represent exactly — the places a duration ends up in JSON.
        let clock = SystemClock::new();
        let first = clock.now_ms();
        assert!(first < 1_000, "the origin is not the process start: {first}");
        let second = clock.now_ms();
        assert!(second >= first);
        assert_eq!(clock.now(), Duration::from_millis(second));
    }

    #[test]
    fn the_system_clock_is_a_clock() {
        // The trait is the seam, so the real implementation has to satisfy it as well as the mock.
        fn reads_a_clock(clock: &dyn Clock) -> u64 {
            clock.now_ms()
        }
        assert!(reads_a_clock(&SystemClock::new()) < 1_000);
        assert_eq!(reads_a_clock(&MockClock::starting_at(7)), 7);
    }

    #[test]
    fn clock_errors_explain_themselves() {
        let errors = [
            ClockError::Backwards { from: 500, to: 400 },
            ClockError::Overflow { from: u64::MAX, by: 1 },
            ClockError::PastTheLimit { to: 1_200, limit: 1_000 },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Advancing a mock clock never produces a reading below the one it started at, whatever sequence of
        /// advances it is given. A monotonic clock that went backwards would make a timeout negative, and code that
        /// waits "until the deadline" then waits forever.
        #[test]
        fn the_reading_never_decreases(advances in proptest::collection::vec(0u64..1_000, 0..50)) {
            let clock = MockClock::starting_at(1);
            let mut previous = clock.now_ms();
            for by in advances {
                let _ = clock.advance(Duration::from_millis(by));
                let now = clock.now_ms();
                prop_assert!(now >= previous, "went from {} to {}", previous, now);
                previous = now;
            }
        }

        /// The sum of the advances that succeeded equals the reading, for any sequence. A clock that lost or gained
        /// time would make a test of a timeout assert about the wrong interval.
        #[test]
        fn the_reading_is_the_sum_of_the_advances(advances in proptest::collection::vec(0u64..1_000, 0..40)) {
            let clock = MockClock::new();
            let mut total = 0u64;
            for by in advances {
                if clock.advance(Duration::from_millis(by)).is_ok() {
                    total += by;
                }
            }
            prop_assert_eq!(clock.now_ms(), total);
        }

        /// A deadline is due exactly from its instant onwards, and not before. The property is the off-by-one the
        /// type exists to prevent.
        #[test]
        fn a_deadline_is_due_from_its_instant(now in 0u64..10_000, after in 0u64..10_000) {
            let deadline = Deadline::after(now, Duration::from_millis(after));
            let at = now + after;
            if at > 0 {
                prop_assert!(!deadline.is_due(at - 1), "due before its instant");
            }
            prop_assert!(deadline.is_due(at));
            prop_assert!(deadline.is_due(at.saturating_add(1)));
        }

        /// The remaining time and the overdue time are never both non-zero: a deadline is either ahead or behind,
        /// and a caller asking both questions must not be told it is in two states at once.
        #[test]
        fn a_deadline_is_never_both_ahead_and_behind(now in 0u64..10_000, at in 0u64..10_000) {
            let deadline = Deadline::at(at);
            let remaining = deadline.remaining(now);
            let overdue = deadline.overdue_by(now);
            prop_assert!(remaining.is_zero() || overdue.is_zero());
            // And at its instant, both are zero.
            if now == at {
                prop_assert!(remaining.is_zero() && overdue.is_zero());
            }
        }
    }
}
