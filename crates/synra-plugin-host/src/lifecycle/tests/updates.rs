use super::super::{Lifecycle, Transition, TransitionError};
use super::active;

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
