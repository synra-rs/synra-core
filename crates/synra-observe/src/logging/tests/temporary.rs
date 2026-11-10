use super::*;

#[test]
fn a_temporary_increase_expires_on_its_own() {
    // The clock is injected, so this asserts the deadline rather than sleeping for thirty minutes.
    let base = std::time::Instant::now();
    let offset = Arc::new(AtomicI64::new(0));
    let offset_for_clock = Arc::clone(&offset);

    let verbosity = Verbosity::with_clock(LogLevel::Info, move || {
        let seconds = offset_for_clock.load(Ordering::Relaxed);
        if seconds >= 0 {
            base + core::time::Duration::from_secs(seconds as u64)
        }
        else {
            base - core::time::Duration::from_secs(seconds.unsigned_abs())
        }
    });

    assert_eq!(verbosity.effective(), LogLevel::Info);
    assert!(!verbosity.is_raised());

    verbosity.raise_for_a_while(LogLevel::Debug);
    assert_eq!(verbosity.effective(), LogLevel::Debug);
    assert!(verbosity.is_raised());
    assert_eq!(verbosity.remaining(), Some(VERBOSE_WINDOW));

    // Just inside the window.
    offset.store(i64::try_from(VERBOSE_WINDOW.as_secs()).expect("small") - 1, Ordering::Relaxed);
    assert_eq!(verbosity.effective(), LogLevel::Debug);

    // Past it.
    offset.store(i64::try_from(VERBOSE_WINDOW.as_secs()).expect("small") + 1, Ordering::Relaxed);
    assert_eq!(verbosity.effective(), LogLevel::Info, "the override must lapse");
    assert!(!verbosity.is_raised());
    assert_eq!(verbosity.remaining(), None);
}

#[test]
fn a_temporary_increase_can_be_ended_immediately() {
    let verbosity = Verbosity::new(LogLevel::Info);
    verbosity.raise_for_a_while(LogLevel::Trace);
    assert_eq!(verbosity.effective(), LogLevel::Trace);

    verbosity.reset();
    assert_eq!(verbosity.effective(), LogLevel::Info);
}

#[test]
fn a_temporary_increase_can_be_given_an_explicit_deadline() {
    // The settings screen shows a countdown, so it already knows the deadline.
    let verbosity = Verbosity::new(LogLevel::Warn);
    let until = std::time::Instant::now() + core::time::Duration::from_secs(60);
    verbosity.raise_until(LogLevel::Debug, until);

    assert_eq!(verbosity.effective(), LogLevel::Debug);
    assert_eq!(verbosity.configured(), LogLevel::Warn);
    // The remaining time is asserted as a range rather than a value: reading the clock between the
    // caller's `Instant::now()` and this assertion makes an exact comparison flaky by nanoseconds.
    let remaining = verbosity.remaining().expect("a deadline is set");
    assert!(
        remaining <= core::time::Duration::from_secs(60)
            && remaining > core::time::Duration::from_secs(59),
        "{remaining:?}",
    );
}

#[test]
fn raising_again_replaces_the_previous_deadline() {
    let verbosity = Verbosity::new(LogLevel::Info);
    verbosity.raise_for_a_while(LogLevel::Debug);
    verbosity.raise_for_a_while(LogLevel::Trace);
    assert_eq!(verbosity.effective(), LogLevel::Trace, "the latest request wins");
}
