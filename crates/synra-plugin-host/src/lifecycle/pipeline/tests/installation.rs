use super::super::super::state::State;
use super::super::{Consent, Progress, FailStage, InstallSource, PluginSlot, Move, MoveError};
use super::{NOW, registry_source, resolved, verified, consented, installed};

#[test]
fn the_pipeline_runs_from_available_to_running() {
    // The whole path, driven from the caller's side at every step: a test that jumped to `Active` would prove the
    // states exist and nothing about the moves between them.
    let mut slot = installed();
    assert_eq!(slot.as_str(), "installed");
    assert_eq!(slot.lifecycle_state(), Some(&State::Granted {
        version: "1.2.3".to_owned(),
        manifest_digest: "aaa".to_owned(),
        partially_denied: false,
    }));

    let _ = slot.apply(Move::Activate, NOW).expect("activate");
    assert_eq!(slot.as_str(), "activating");
    let _ = slot.apply(Move::Activated, NOW).expect("activated");
    assert_eq!(slot.as_str(), "active");
    assert!(slot.is_running());

    let _ = slot.apply(Move::Deactivate, NOW).expect("deactivate");
    assert_eq!(slot.as_str(), "deactivating");
    let _ = slot.apply(Move::Deactivated, NOW).expect("deactivated");
    assert_eq!(slot.as_str(), "installed");
    assert_eq!(slot.lifecycle_state().map(State::as_str), Some("deactivated"));
}

#[test]
fn a_local_source_is_only_installed_by_a_development_build() {
    // ★ The rule from §2.1.2. In a release build a local path is a way to run unsigned code, and the refusal is
    // here rather than in the resolver because it is about *this build* rather than about the source.
    let mut slot = PluginSlot::available();
    let local = InstallSource::Local { path: "./hello".to_owned() };
    let refused = slot.apply(Move::Install { source: local }, NOW);

    if cfg!(debug_assertions) {
        assert!(refused.is_ok(), "a development build accepts a local source");
        assert_eq!(slot.as_str(), "resolving");
    }
    else {
        assert!(matches!(refused, Err(MoveError::LocalInstallNotAllowed)), "{refused:?}");
        assert_eq!(slot.as_str(), "available", "a refused install leaves the slot where it was");
    }
    assert!(InstallSource::Local { path: "x".to_owned() }.refuses_outside_development());
    assert!(!registry_source().refuses_outside_development());
}

#[test]
fn every_stage_refuses_the_move_that_belongs_to_another() {
    // A caller that skips verification must be told so rather than reaching `Active` with unchecked code.
    let mut slot = PluginSlot::available();
    for step in [
        Move::Verified { verified: verified() },
        Move::Consented { consent: consented() },
        Move::Installed,
        Move::Activated,
        Move::Activated,
        Move::Deactivated,
        Move::ClearFault,
        Move::Removed,
    ] {
        // The step is cloned for the message rather than moved into the call: a refusal has to name what was
        // attempted, and the assertion below is where that name is read.
        let refused = slot.apply(step.clone(), NOW);
        assert!(refused.is_err(), "{step:?} was accepted while available");
    }
}

#[test]
fn progress_never_goes_backwards() {
    // A stalled connection retried inside one request reports less than it did; drawing that would make a download
    // appear to restart.
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
    let _ = slot.apply(Move::Downloaded { progress: Progress { received: 900, total: Some(1_000) } }, NOW);
    let _ = slot.apply(Move::Downloaded { progress: Progress { received: 100, total: None } }, NOW);

    let PluginSlot::Downloading { progress, .. } = &slot else {
        panic!("expected a download");
    };
    assert_eq!(progress.received, 900);
    assert_eq!(progress.total, Some(1_000), "a total that was known stays known");
    assert_eq!(progress.fraction(), Some(0.9));
}

#[test]
fn a_refused_consent_ends_the_install_without_blaming_the_plugin() {
    // A user saying no is a decision, not a breakage: the stage is `Consent`, the sentence says so, and a retry
    // button would be offering to ask again without saying that is what it does.
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
    let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
    let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
    let _ = slot
        .apply(Move::Consented { consent: Consent { granted: Vec::new(), denied: vec!["log:*".to_owned()] } }, NOW)
        .expect("consented");

    let PluginSlot::Failed(failed) = &slot else {
        panic!("expected a failure, got {slot:?}");
    };
    assert_eq!(failed.stage, FailStage::Consent);
    assert!(!failed.retryable, "asking again is the user's decision, not a retry button");
    assert!(!slot.can_retry());
}

#[test]
fn a_partial_consent_installs_and_is_recorded_as_partial() {
    // A plugin running with some capabilities denied behaves differently, and the record has to say which.
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
    let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
    let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
    let _ = slot
        .apply(
            Move::Consented {
                consent: Consent {
                    granted: vec!["log:*".to_owned()],
                    denied: vec!["platform:open-url".to_owned()],
                },
            },
            NOW,
        )
        .expect("consented");
    let _ = slot.apply(Move::Installed, NOW).expect("installed");

    assert_eq!(
        slot.lifecycle_state(),
        Some(&State::Granted {
            version: "1.2.3".to_owned(),
            manifest_digest: "aaa".to_owned(),
            partially_denied: true,
        })
    );
}
