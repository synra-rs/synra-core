use super::{Direction, play, x11_key, x11_modifier};
use crate::{KeyChord, PlatformError};

fn attempt(failures: &[(u8, Direction)]) -> (Result<(), PlatformError>, Vec<(u8, Direction)>) {
    let mut events = Vec::new();
    let outcome = play([1, 2].into_iter(), 3, |key, direction| {
        events.push((*key, direction));
        if failures.contains(&(*key, direction)) {
            return Err(PlatformError::RunnerFailed {
                program: "recording keyboard".to_owned(),
                reason: format!("{direction:?} {key}"),
            });
        }
        Ok(())
    });
    (outcome, events)
}

#[test]
fn a_chord_releases_its_main_key_then_its_modifiers_in_reverse_order() {
    use Direction::{Down, Up};

    let (outcome, events) = attempt(&[]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(
        events,
        [(1, Down), (2, Down), (3, Down), (3, Up), (2, Up), (1, Up)]
    );
}

#[test]
fn failure_at_each_press_releases_every_successful_press() {
    use Direction::{Down, Up};

    for (failed, events) in [
        (1, vec![(1, Down)]),
        (2, vec![(1, Down), (2, Down), (1, Up)]),
        (3, vec![(1, Down), (2, Down), (3, Down), (2, Up), (1, Up)]),
    ] {
        let (outcome, recorded) = attempt(&[(failed, Down)]);
        assert!(
            outcome
                .unwrap_err()
                .to_string()
                .ends_with(&format!("Down {failed}"))
        );
        assert_eq!(recorded, events);
    }
}

#[test]
fn a_release_failure_keeps_the_press_error_and_attempts_remaining_releases() {
    use Direction::{Down, Up};

    let (outcome, events) = attempt(&[(3, Down), (2, Up), (1, Up)]);
    assert_eq!(events, [(1, Down), (2, Down), (3, Down), (2, Up), (1, Up)]);
    let PlatformError::KeyReleaseFailed {
        input: Some(input),
        failures,
    } = outcome.unwrap_err()
    else {
        panic!("expected input and release diagnostics");
    };
    assert!(input.ends_with("Down 3"));
    assert!(failures[0].ends_with("Up 2"));
    assert!(failures[1].ends_with("Up 1"));

    let (outcome, events) = attempt(&[(3, Up)]);
    assert_eq!(
        events,
        [(1, Down), (2, Down), (3, Down), (3, Up), (2, Up), (1, Up)]
    );
    assert!(matches!(
        outcome,
        Err(PlatformError::KeyReleaseFailed { input: None, .. })
    ));
}

#[test]
fn timeout_also_releases_a_key_that_may_have_been_pressed() {
    use Direction::{Down, Up};

    let timeout = PlatformError::RunnerTimedOut {
        program: "xdotool".to_owned(),
        timeout_ms: 5_000,
        cleanup_pending: false,
    };
    let mut events = Vec::new();
    let outcome = play([1, 2].into_iter(), 3, |&key, direction| {
        events.push((key, direction));
        if (key, direction) == (2, Down) {
            return Err(timeout.clone());
        }
        Ok(())
    });
    assert_eq!(outcome, Err(timeout));
    assert_eq!(events, [(1, Down), (2, Down), (2, Up), (1, Up)]);
}

#[test]
fn x11_uses_only_generated_key_symbols() {
    for (input, modifiers, key) in [
        ("Ctrl+Shift+S", vec!["Control_L", "Shift_L"], "s"),
        ("Alt+Tab", vec!["Alt_L"], "Tab"),
        ("Meta+E", vec!["Super_L"], "e"),
        ("Ctrl+NumpadAdd", vec!["Control_L"], "KP_Add"),
        ("PageDown", vec![], "Next"),
    ] {
        let chord: KeyChord = input.parse().unwrap();
        assert_eq!(
            chord.modifiers().map(x11_modifier).collect::<Vec<_>>(),
            modifiers
        );
        assert_eq!(x11_key(chord.key()), key);
    }
}
