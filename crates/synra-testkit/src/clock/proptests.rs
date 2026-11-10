use core::time::Duration;

use proptest::prelude::*;

use super::{Clock, Deadline, MockClock};

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
