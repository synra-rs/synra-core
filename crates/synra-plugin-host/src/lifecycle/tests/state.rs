use super::super::{State, Transition, TransitionError};

#[test]
fn every_state_carries_a_version_except_an_empty_park() {
    let states = [
        State::Installed { version: "1".to_owned() },
        State::Validated { version: "1".to_owned(), manifest_digest: "d".to_owned() },
        State::Granted {
            version: "1".to_owned(),
            manifest_digest: "d".to_owned(),
            partially_denied: false,
        },
        State::Active { version: "1".to_owned(), partially_denied: false },
        State::Deactivated { version: "1".to_owned() },
        State::Faulted { version: "1".to_owned(), reason: "r".to_owned() },
        State::Parked { version: Some("1".to_owned()) },
    ];
    for state in states {
        assert_eq!(state.version(), Some("1"), "{state:?}");
        assert!(!state.describe().is_empty(), "{state:?}");
        assert!(!state.as_str().is_empty(), "{state:?}");
    }
    assert_eq!(State::Parked { version: None }.version(), None);
}

#[test]
fn only_active_counts_as_running() {
    let states = [
        (State::Installed { version: "1".to_owned() }, false),
        (State::Validated { version: "1".to_owned(), manifest_digest: "d".to_owned() }, false),
        (State::Active { version: "1".to_owned(), partially_denied: false }, true),
        (State::Deactivated { version: "1".to_owned() }, false),
        (State::Faulted { version: "1".to_owned(), reason: "r".to_owned() }, false),
        (State::Parked { version: None }, false),
    ];
    for (state, running) in states {
        assert_eq!(state.is_running(), running, "{state:?}");
    }
}

#[test]
fn holding_loaded_code_is_what_forces_parking() {
    assert!(!State::Installed { version: "1".to_owned() }.holds_loaded_code());
    assert!(!State::Parked { version: None }.holds_loaded_code());
    for state in [
        State::Validated { version: "1".to_owned(), manifest_digest: "d".to_owned() },
        State::Granted {
            version: "1".to_owned(),
            manifest_digest: "d".to_owned(),
            partially_denied: false,
        },
        State::Active { version: "1".to_owned(), partially_denied: false },
        State::Deactivated { version: "1".to_owned() },
        State::Faulted { version: "1".to_owned(), reason: "r".to_owned() },
    ] {
        assert!(state.holds_loaded_code(), "{state:?}");
    }
}

#[test]
fn a_state_displays_its_name() {
    assert_eq!(State::Parked { version: None }.to_string(), "parked");
}

#[test]
fn a_state_survives_a_round_trip() {
    // The state is persisted between runs, so its shape is part of what an upgrade has to keep readable.
    for state in [
        State::Installed { version: "1.0.0".to_owned() },
        State::Validated { version: "1.0.0".to_owned(), manifest_digest: "d".to_owned() },
        State::Active { version: "1.0.0".to_owned(), partially_denied: true },
        State::Faulted { version: "1.0.0".to_owned(), reason: "trapped".to_owned() },
        State::Parked { version: None },
    ] {
        let json = serde_json::to_string(&state).expect("serialises");
        let back: State = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, state, "{json}");
    }
}

#[test]
fn a_faulted_state_survives_a_round_trip_with_its_reason() {
    let state = State::Faulted { version: "1".to_owned(), reason: "ran out of fuel".to_owned() };
    let json = serde_json::to_string(&state).expect("serialises");
    assert!(json.contains("ran out of fuel"), "{json}");
}

#[test]
fn every_transition_has_a_name_for_a_log_line() {
    let transitions = [
        Transition::Validate { manifest_digest: "d".to_owned() },
        Transition::Grant { partially_denied: false },
        Transition::Activate,
        Transition::Deactivate,
        Transition::Fault { reason: "r".to_owned() },
        Transition::Park,
        Transition::Uninstall,
        Transition::Upgrade { version: "2".to_owned() },
    ];
    for transition in transitions {
        let name = transition.as_str();
        assert!(!name.is_empty(), "{transition:?}");
        assert!(!name.contains(' '), "{transition:?} -> {name}");
    }
}

#[test]
fn transition_errors_explain_themselves() {
    let errors = [
        TransitionError::WrongState { state: "parked", transition: "activate" },
        TransitionError::NeedsParking { transition: "uninstalled" },
        TransitionError::Faulted { reason: "exceeded its limits".to_owned() },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
