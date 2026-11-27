use super::super::actions::{MAX_NOTIFICATION_LEN, MAX_CHORD_LEN};
use super::super::error::PlatformError;
use super::super::guard::check_notification;
use crate::{KeyChord, KeyChordError};

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
fn a_single_chord_normalizes_modifiers_and_key_names() {
    for (input, expected) in [
        ("shift + ctrl + s", "Ctrl+Shift+S"),
        ("alt+TAB", "Alt+Tab"),
        ("meta+e", "Meta+E"),
        ("ctrl+NumpadAdd", "Ctrl+NumpadAdd"),
        ("shift+f12", "Shift+F12"),
        ("0", "0"),
        ("pageup", "PageUp"),
    ] {
        let chord = input.parse::<KeyChord>().unwrap();
        assert_eq!(chord.to_string(), expected);
        assert_eq!(chord.to_string().parse(), Ok(chord));
    }
}

#[test]
fn malformed_chords_report_the_parse_failure() {
    for (input, reason) in [
        ("   ", KeyChordError::EmptyPart),
        ("Ctrl++", KeyChordError::EmptyPart),
        ("Ctrl+CTRL+C", KeyChordError::DuplicateModifier),
        ("Ctrl+Shift", KeyChordError::MissingKey),
        ("c+d", KeyChordError::ExpectedModifier),
        ("cmd+c", KeyChordError::ExpectedModifier),
        ("Ctrl+F01", KeyChordError::UnknownKey),
        ("Ctrl+F13", KeyChordError::UnknownKey),
        ("^c", KeyChordError::UnknownKey),
        ("Ctrl+S Alt+F4", KeyChordError::ExpectedModifier),
    ] {
        assert_eq!(input.parse::<KeyChord>(), Err(PlatformError::BadKeyChord(reason)), "{input}");
    }
    assert!(matches!(
        "x".repeat(MAX_CHORD_LEN + 1).parse::<KeyChord>(),
        Err(PlatformError::TooLong { field: "key chord", .. })
    ));
}
