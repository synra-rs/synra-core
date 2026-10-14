//! The lifecycle's tests.

use super::*;

/// A lifecycle taken to `Granted`.
fn granted() -> Lifecycle {
    let mut lifecycle = Lifecycle::installed("1.0.0");
    lifecycle
        .apply(Transition::Validate { manifest_digest: "d1".to_owned() })
        .expect("validates");
    lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
    lifecycle
}

/// A lifecycle taken to `Active`.
fn active() -> Lifecycle {
    let mut lifecycle = granted();
    lifecycle.apply(Transition::Activate).expect("activates");
    lifecycle
}

#[test]
fn a_new_plugin_is_installed_and_not_running() {
    let lifecycle = Lifecycle::installed("1.0.0");
    assert_eq!(lifecycle.state().as_str(), "installed");
    assert_eq!(lifecycle.state().version(), Some("1.0.0"));
    assert!(!lifecycle.is_running());
    assert!(!lifecycle.state().can_activate());
}

#[test]
fn the_ordinary_path_runs_through_every_state() {
    let mut lifecycle = Lifecycle::installed("1.0.0");
    assert_eq!(lifecycle.state().as_str(), "installed");

    lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
    assert_eq!(lifecycle.state().as_str(), "validated");

    lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
    assert_eq!(lifecycle.state().as_str(), "granted");
    assert_eq!(lifecycle.granted_digest(), Some("d"));

    lifecycle.apply(Transition::Activate).expect("activates");
    assert_eq!(lifecycle.state().as_str(), "active");
    assert!(lifecycle.is_running());

    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    assert_eq!(lifecycle.state().as_str(), "deactivated");
    assert!(!lifecycle.is_running());

    lifecycle.apply(Transition::Park).expect("parks");
    assert_eq!(lifecycle.state().as_str(), "parked");
}

#[test]
fn a_plugin_may_not_run_before_its_grants_are_decided() {
    // A plugin that runs first and asks later is one whose first action was unauthorised.
    let mut lifecycle = Lifecycle::installed("1.0.0");
    match lifecycle.apply(Transition::Activate) {
        Err(TransitionError::WrongState { state, transition }) => {
            assert_eq!(state, "installed");
            assert_eq!(transition, "activate");
        }
        other => panic!("expected a state refusal, got {other:?}"),
    }

    // Nor after validation, before the decision.
    lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
    assert!(lifecycle.apply(Transition::Activate).is_err());
}

#[test]
fn a_granted_plugin_may_run() {
    assert!(granted().state().can_activate());
    let mut lifecycle = granted();
    lifecycle.apply(Transition::Activate).expect("activates");
    assert!(lifecycle.is_running());
}

#[test]
fn granting_again_replaces_the_decision_rather_than_failing() {
    // A user who changes their mind is not making a mistake.
    let mut lifecycle = granted();
    lifecycle.apply(Transition::Grant { partially_denied: true }).expect("re-grants");
    assert!(matches!(lifecycle.state(), State::Granted { partially_denied: true, .. }));
}

#[test]
fn a_partially_denied_plugin_records_it() {
    // A plugin running with some capabilities denied behaves differently from one running with all of them, and a
    // bug report that does not say which is a bug report about a different plugin.
    let mut lifecycle = Lifecycle::installed("1.0.0");
    lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
    lifecycle.apply(Transition::Grant { partially_denied: true }).expect("grants");
    lifecycle.apply(Transition::Activate).expect("activates");
    assert!(matches!(lifecycle.state(), State::Active { partially_denied: true, .. }));
    assert!(lifecycle.state().describe().contains("fewer permissions"), "{}", lifecycle.state().describe());
}

#[test]
fn a_deactivated_plugin_restarts_without_a_new_decision() {
    // It kept its grants, so re-running the consent screen would ask the user to decide the same thing twice.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    lifecycle.apply(Transition::Activate).expect("restarts");
    assert!(lifecycle.is_running());
    assert_eq!(lifecycle.granted_digest(), Some("d1"));
}

#[test]
fn a_faulted_plugin_may_not_be_activated() {
    // The ladder's last rung has to mean something, and a caller that could reactivate by asking again would make
    // it decorative.
    let mut lifecycle = active();
    lifecycle
        .apply(Transition::Fault { reason: "exceeded its limits".to_owned() })
        .expect("faults");
    assert_eq!(lifecycle.state().as_str(), "faulted");

    match lifecycle.apply(Transition::Activate) {
        Err(TransitionError::Faulted { reason }) => assert!(reason.contains("limits")),
        other => panic!("expected a faulted refusal, got {other:?}"),
    }
}

#[test]
fn a_fault_carries_a_reason_the_interface_can_show() {
    // A faulted plugin with no explanation is a plugin the user cannot decide about.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Fault { reason: "trapped".to_owned() }).expect("faults");
    assert!(lifecycle.state().describe().contains("trapped"));
}

#[test]
fn deactivating_a_plugin_that_is_not_running_is_refused() {
    let mut lifecycle = granted();
    assert!(lifecycle.apply(Transition::Deactivate).is_err());
}

#[test]
fn an_active_plugin_may_not_be_parked() {
    // Parking an active plugin is the caller forgetting to deactivate it, and doing it silently would leave the
    // plugin running against freed state.
    let mut lifecycle = active();
    assert!(lifecycle.apply(Transition::Park).is_err());
    // After deactivating, it may.
    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    assert!(lifecycle.apply(Transition::Park).is_ok());
}

#[test]
fn an_active_plugin_may_not_be_uninstalled() {
    // Uninstalling removes the artifact, and a running instance would then be executing code that no longer
    // exists on disk. This is the transition the host must not shortcut, because "uninstall" is what a user does
    // when they are worried about a plugin.
    let mut lifecycle = active();
    match lifecycle.apply(Transition::Uninstall) {
        Err(TransitionError::NeedsParking { transition }) => assert_eq!(transition, "uninstalled"),
        other => panic!("expected a parking requirement, got {other:?}"),
    }
    // And the error says there is a step to perform rather than that the caller made a mistake.
    assert!(TransitionError::NeedsParking { transition: "uninstalled" }.has_a_next_step());
}

#[test]
fn the_way_to_uninstall_a_running_plugin_is_to_stop_it_first() {
    let mut lifecycle = active();
    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    lifecycle.apply(Transition::Park).expect("parks");
    lifecycle.apply(Transition::Uninstall).expect("uninstalls");
    assert_eq!(lifecycle.state().as_str(), "parked");
    assert_eq!(lifecycle.state().version(), None);
    assert_eq!(lifecycle.granted_digest(), None, "the grants went with the plugin");
}

#[test]
fn an_installed_plugin_may_be_uninstalled_without_parking() {
    // Nothing has loaded, so there is nothing to stop.
    let mut lifecycle = Lifecycle::installed("1.0.0");
    assert!(lifecycle.apply(Transition::Uninstall).is_ok());
}

#[test]
fn a_validated_plugin_must_be_parked_before_it_can_be_uninstalled() {
    // Validation resolved the artifacts and read the module, so removing the package under it would leave the
    // host holding a description of something that is gone.
    let mut lifecycle = Lifecycle::installed("1.0.0");
    lifecycle.apply(Transition::Validate { manifest_digest: "d".to_owned() }).expect("validates");
    assert!(lifecycle.state().holds_loaded_code());
    assert!(!lifecycle.state().can_uninstall());
    assert!(matches!(
        lifecycle.apply(Transition::Uninstall),
        Err(TransitionError::NeedsParking { .. })
    ));

    // And parking is the step that unsticks it.
    lifecycle.apply(Transition::Park).expect("parks");
    assert!(lifecycle.apply(Transition::Uninstall).is_ok());
}

#[test]
fn a_fault_is_cleared_only_deliberately() {
    // Parking and upgrading are housekeeping steps a caller may take for unrelated reasons, so neither may
    // silently clear a fault — that would make the ladder's last rung decorative.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Fault { reason: "traps".to_owned() }).expect("faults");

    lifecycle.apply(Transition::Park).expect("parks");
    assert_eq!(lifecycle.state().as_str(), "parked");
    // The fault is remembered even through an upgrade: the new artifact has to be validated and granted again.
    lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }).expect("upgrades");
    lifecycle.apply(Transition::Validate { manifest_digest: "d2".to_owned() }).expect("validates");
    // Activating now is legitimate: this is a different artifact that has been through the whole path again.
    lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
    assert!(lifecycle.apply(Transition::Activate).is_ok());
}

#[test]
fn clearing_a_fault_returns_to_validated() {
    // The manifest was checked before the fault, but the user is being asked to re-enable a plugin that
    // misbehaved, so the decision is theirs to make again.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Fault { reason: "traps".to_owned() }).expect("faults");

    lifecycle.apply(Transition::ClearFault).expect("clears");
    assert_eq!(lifecycle.state().as_str(), "validated");
    // And it may be granted and run again.
    lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
    assert!(lifecycle.apply(Transition::Activate).is_ok());
}

#[test]
fn clearing_a_fault_that_is_not_there_is_refused() {
    // A caller that clears a fault on a healthy plugin has misunderstood the state, and silently accepting would
    // hide the misunderstanding.
    let mut lifecycle = active();
    assert!(lifecycle.apply(Transition::ClearFault).is_err());
}

#[test]
fn parking_from_a_faulted_state_is_allowed() {
    // The user has to be able to remove a plugin that broke.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Fault { reason: "x".to_owned() }).expect("faults");
    assert!(lifecycle.apply(Transition::Park).is_ok());
    assert!(lifecycle.apply(Transition::Uninstall).is_ok());
}

#[test]
fn an_upgrade_returns_to_installed_and_clears_the_digest() {
    // Nothing about the new artifact has been checked, so it cannot be `Validated`, and the recorded digest is
    // about the old manifest.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    lifecycle.apply(Transition::Park).expect("parks");

    lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }).expect("upgrades");
    assert_eq!(lifecycle.state().as_str(), "installed");
    assert_eq!(lifecycle.state().version(), Some("2.0.0"));
    assert_eq!(lifecycle.granted_digest(), None);
}

#[test]
fn an_upgrade_of_a_running_plugin_needs_parking() {
    let mut lifecycle = active();
    match lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }) {
        Err(TransitionError::NeedsParking { transition }) => assert_eq!(transition, "upgraded"),
        other => panic!("expected a parking requirement, got {other:?}"),
    }
}

#[test]
fn an_upgrade_that_changed_nothing_keeps_the_grants() {
    // Comparing digests rather than showing every permission again is what makes a version bump that changed
    // nothing invisible to the user.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    lifecycle.apply(Transition::Park).expect("parks");

    assert!(lifecycle.upgrade_keeps_grants("d1"), "an unchanged manifest should keep its grants");
    assert!(!lifecycle.upgrade_keeps_grants("d2"), "a changed manifest must ask again");
}

#[test]
fn a_plugin_that_never_granted_anything_keeps_no_grants() {
    let lifecycle = Lifecycle::parked();
    assert!(!lifecycle.upgrade_keeps_grants("d1"));
    assert_eq!(lifecycle.granted_digest(), None);
}

#[test]
fn only_a_parked_plugin_keeps_grants_across_an_upgrade() {
    // `upgrade_keeps_grants` requires the state to be replaceable, so a running plugin is not silently counted as
    // keeping grants it is about to have re-decided.
    let mut lifecycle = active();
    lifecycle.apply(Transition::Deactivate).expect("deactivates");
    assert!(!lifecycle.state().can_uninstall(), "deactivated still holds loaded code");
    assert!(!lifecycle.upgrade_keeps_grants("d1"));

    lifecycle.apply(Transition::Park).expect("parks");
    assert!(lifecycle.upgrade_keeps_grants("d1"));
}

// ── States ────────────────────────────────────────────────────────────────────────────────────

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

// ── Stop history ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_version_that_has_not_stopped_is_stable() {
    let record = StopRecord::new("1.0.0");
    assert!(!record.is_unstable());
    assert_eq!(record.unexpected_stops, 0);
    assert_eq!(record.last_reason, None);
}

#[test]
fn three_unexpected_stops_make_a_version_unstable() {
    // A plugin that has crashed three times in a row is not going to work on the fourth.
    let mut record = StopRecord::new("1.0.0");
    for _ in 0..UNSTABLE_THRESHOLD - 1 {
        record.record_unexpected_stop("trapped");
        assert!(!record.is_unstable());
    }
    record.record_unexpected_stop("trapped");
    assert!(record.is_unstable());
    assert_eq!(record.last_reason.as_deref(), Some("trapped"));
}

#[test]
fn the_stop_count_saturates_rather_than_wrapping() {
    // A wrapping count would make a plugin that crashed four billion times look like one that never crashed.
    let mut record = StopRecord::new("1.0.0");
    record.unexpected_stops = u32::MAX;
    record.record_unexpected_stop("again");
    assert_eq!(record.unexpected_stops, u32::MAX);
    assert!(record.is_unstable());
}

#[test]
fn a_stop_record_survives_a_round_trip() {
    let mut record = StopRecord::new("1.0.0");
    record.record_unexpected_stop("trapped");
    let json = serde_json::to_string(&record).expect("serialises");
    assert!(json.contains("unexpectedStops"), "{json}");
    let back: StopRecord = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, record);
}
