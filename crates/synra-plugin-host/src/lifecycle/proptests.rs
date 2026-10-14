//! The lifecycle's property tests.

use super::*;
use proptest::prelude::*;

/// A transition to try, generated without its payload.
fn arbitrary_transition() -> impl Strategy<Value = Transition> {
    prop_oneof![
        Just(Transition::Validate { manifest_digest: "d".to_owned() }),
        Just(Transition::Grant { partially_denied: false }),
        Just(Transition::Grant { partially_denied: true }),
        Just(Transition::Activate),
        Just(Transition::Deactivate),
        Just(Transition::Fault { reason: "r".to_owned() }),
        Just(Transition::Park),
        Just(Transition::ClearFault),
        Just(Transition::Uninstall),
        Just(Transition::Upgrade { version: "2.0.0".to_owned() }),
    ]
}

/// What resets the fault tracker.
///
/// A **new artifact** is a different program: it goes through validation and a fresh decision, which is the
/// recovery path the type documents. Housekeeping on the *same* artifact — parking it, deactivating it, clearing
/// the fault — does not make the faulted code work, so a plugin that reaches `Active` afterwards must have
/// arrived through an upgrade.
fn resets_fault(step: &Transition) -> bool {
    matches!(step, Transition::Upgrade { .. } | Transition::ClearFault)
}

proptest! {
    /// Whatever sequence of transitions is applied, the lifecycle never reaches a state where a plugin is running
    /// without having been granted. It is the invariant the whole type exists for: a plugin that runs before the
    /// user decides is one whose first action was unauthorised.
    #[test]
    fn a_running_plugin_was_always_granted_first(
        steps in proptest::collection::vec(arbitrary_transition(), 0..40)
    ) {
        let mut lifecycle = Lifecycle::installed("1.0.0");
        let mut ever_granted = false;

        for step in steps {
            let _ = lifecycle.apply(step);
            if matches!(lifecycle.state(), State::Granted { .. } | State::Active { .. } | State::Deactivated { .. }) {
                ever_granted = true;
            }
            if lifecycle.is_running() {
                prop_assert!(ever_granted, "running at {:?} without ever being granted", lifecycle.state());
                prop_assert!(lifecycle.granted_digest().is_some(), "running with no recorded digest");
            }
        }
    }

    /// Whatever the sequence, applying a transition either moves the state or leaves it alone, and the reported
    /// state always matches what the accessors say. A state and its own predicates disagreeing is the kind of
    /// defect that shows up as a plugin that the interface says is running and the host treats as stopped.
    #[test]
    fn the_state_and_its_predicates_always_agree(
        steps in proptest::collection::vec(arbitrary_transition(), 0..40)
    ) {
        let mut lifecycle = Lifecycle::installed("1.0.0");
        for step in steps {
            let _ = lifecycle.apply(step);
            let state = lifecycle.state();
            prop_assert_eq!(lifecycle.is_running(), state.is_running());
            prop_assert_eq!(state.is_running(), matches!(state, State::Active { .. }));
            if state.can_uninstall() {
                prop_assert!(!state.holds_loaded_code(), "uninstallable but holding code: {state:?}");
            }
            // A version is carried by everything except an empty park.
            if !matches!(state, State::Parked { version: None }) {
                prop_assert!(state.version().is_some(), "{state:?} carries no version");
            }
        }
    }

    /// A faulted plugin never becomes active again through transitions alone. Climbing out has to be a deliberate
    /// act by a caller, or the ladder's last rung is decorative.
    #[test]
    fn faulted_never_returns_to_active_alone(
        steps in proptest::collection::vec(arbitrary_transition(), 0..40)
    ) {
        let mut lifecycle = Lifecycle::installed("1.0.0");
        let mut became_faulted = false;

        for step in steps {
            if resets_fault(&step) {
                became_faulted = false;
            }
            let _ = lifecycle.apply(step);
            if matches!(lifecycle.state(), State::Faulted { .. }) {
                became_faulted = true;
            }
            if became_faulted {
                prop_assert!(
                    !lifecycle.is_running(),
                    "a faulted plugin returned to active through {:?}",
                    lifecycle.state(),
                );
            }
        }
    }

    /// An upgrade always lands on `Installed`, so nothing about the new artifact is assumed to have been checked.
    /// Landing anywhere else would let a caller skip validation by upgrading.
    #[test]
    fn an_upgrade_always_lands_on_installed(prefix in proptest::collection::vec(arbitrary_transition(), 0..20)) {
        let mut lifecycle = Lifecycle::installed("1.0.0");
        for step in prefix {
            let _ = lifecycle.apply(step);
        }
        let _ = lifecycle.apply(Transition::Park);
        let _ = lifecycle.apply(Transition::Uninstall);

        if lifecycle.apply(Transition::Upgrade { version: "2.0.0".to_owned() }).is_ok() {
            prop_assert!(
                matches!(lifecycle.state(), State::Installed { .. }),
                "an upgrade landed on {:?}",
                lifecycle.state(),
            );
        }
    }
}
