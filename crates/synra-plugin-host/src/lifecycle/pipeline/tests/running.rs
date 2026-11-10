use super::super::super::state::State;
use super::super::{Progress, PluginSlot, Move, MoveError};
use super::{NOW, registry_source, resolved, verified, consented, installed};

#[test]
fn a_fault_from_running_is_a_state_and_the_user_can_clear_it() {
    let mut slot = installed();
    let _ = slot.apply(Move::Activate, NOW).expect("activate");
    let _ = slot.apply(Move::Activated, NOW).expect("activated");
    let _ = slot
        .apply(Move::Fault { reason: "exceeded its quota".to_owned() }, NOW)
        .expect("faulted");

    assert_eq!(slot.as_str(), "faulted");
    assert!(slot.describe().contains("exceeded its quota"), "{}", slot.describe());
    // Not running, but still present: a faulted plugin is one the user still has.
    assert!(!slot.is_running());
    assert!(slot.is_present());

    let _ = slot.apply(Move::ClearFault, NOW).expect("cleared");
    assert_eq!(slot.as_str(), "installed");
    assert_eq!(slot.lifecycle_state().map(State::as_str), Some("validated"));
}

#[test]
fn a_fault_while_activating_is_recorded_where_it_happened() {
    // The case that matters: the module loaded and its start function trapped. Nothing is running, and the plugin
    // is not "installed and fine" either.
    let mut slot = installed();
    let _ = slot.apply(Move::Activate, NOW).expect("activate");
    let _ = slot
        .apply(Move::Fault { reason: "the start function trapped".to_owned() }, NOW)
        .expect("faulted");

    assert_eq!(slot.as_str(), "faulted");
    assert!(slot.lifecycle_state().is_some());
}

#[test]
fn a_running_plugin_is_stopped_before_it_is_removed() {
    // Removing an active plugin would take the artifact out from under a live instance. The caller has a step to
    // perform, and the refusal says which.
    let mut slot = installed();
    let _ = slot.apply(Move::Activate, NOW).expect("activate");
    let _ = slot.apply(Move::Activated, NOW).expect("activated");

    match slot.apply(Move::Remove, NOW) {
        Err(MoveError::WrongState { attempted, current }) => {
            assert_eq!(attempted, "remove");
            assert_eq!(current, "active");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    let _ = slot.apply(Move::Deactivate, NOW).expect("deactivate");
    let _ = slot.apply(Move::Deactivated, NOW).expect("deactivated");
    let _ = slot.apply(Move::Remove, NOW).expect("remove");
    assert_eq!(slot.as_str(), "removing");
}

#[test]
fn removal_ends_at_available_with_nothing_left() {
    let mut slot = installed();
    let _ = slot.apply(Move::Remove, NOW).expect("remove");
    let _ = slot.apply(Move::Removed, NOW).expect("removed");

    assert_eq!(slot, PluginSlot::Available);
    assert!(!slot.is_present());
    assert!(slot.lifecycle().is_none());
}

#[test]
fn a_cancellable_state_is_the_one_where_nothing_is_half_written() {
    // The list is a claim about what cancelling leaves behind, so it is asserted rather than described.
    assert!(PluginSlot::Resolving { source: registry_source() }.is_cancellable());
    assert!(
        PluginSlot::AwaitingConsent { source: registry_source(), verified: verified() }.is_cancellable(),
        "a prompt nobody has answered is the easiest thing in the world to withdraw"
    );
    let removing = {
        let mut slot = installed();
        let _ = slot.apply(Move::Remove, NOW).expect("remove");
        slot
    };
    assert!(removing.is_cancellable());

    // ★ And the two states where cancelling would leave something half-done are not:
    // `Installing` is renaming an artifact into place, and `Active` is not a stage at all.
    let installing = {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW);
        let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW);
        let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW);
        let _ = slot.apply(Move::Verified { verified: verified() }, NOW);
        let _ = slot.apply(Move::Consented { consent: consented() }, NOW);
        slot
    };
    assert_eq!(installing.as_str(), "installing");
    assert!(!installing.is_cancellable(), "the artifact is being renamed into place");

    assert!(!PluginSlot::Available.is_cancellable());
    assert!(!installed().is_cancellable(), "installed is not a stage something is happening in");
}

#[test]
fn a_clock_change_does_not_move_a_download_backwards() {
    // Progress is bytes, not time, so this is the one place a clock cannot hurt — asserted because "progress" is
    // the kind of field somebody later divides by an elapsed time.
    let progress = Progress { received: 500, total: Some(1_000) };
    assert_eq!(progress.fraction(), Some(0.5));
    assert!(!progress.is_complete());
    assert_eq!(Progress { received: 10, total: None }.fraction(), None);
    assert_eq!(Progress { received: 0, total: Some(0) }.fraction(), Some(1.0));
    assert!(Progress { received: 1_000, total: Some(1_000) }.is_complete());
}
