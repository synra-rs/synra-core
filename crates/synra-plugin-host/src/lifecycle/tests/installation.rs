use super::super::{Lifecycle, State, Transition, TransitionError};
use super::granted;

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
