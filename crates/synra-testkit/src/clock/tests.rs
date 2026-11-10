use core::time::Duration;

use super::{Clock, ClockError, Deadline, MockClock, SystemClock};

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
