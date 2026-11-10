use super::super::{Lifecycle, Transition, TransitionError};
use super::{active, granted};

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
