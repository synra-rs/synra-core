use core::time::Duration;
use super::super::actions::{PlatformAction, Policies};
use super::super::error::PlatformError;
use super::super::guard::RateLimiter;

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
