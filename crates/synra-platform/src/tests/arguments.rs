use super::super::actions::{MAX_NOTIFICATION_LEN, MAX_CHORD_LEN};
use super::super::error::PlatformError;
use super::super::guard::{check_notification, check_key_chord};

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
