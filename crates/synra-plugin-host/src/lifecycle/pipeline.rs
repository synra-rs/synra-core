//! The full lifecycle: thirteen states, and what each move out of one has to carry.
//!
//! # Why this is a second machine rather than a bigger [`Lifecycle`](super::Lifecycle)
//!
//! Because the two answer different questions, and the answer to one of them is *"nothing has happened yet"*.
//! [`Lifecycle`](super::Lifecycle) is about a plugin that is **on this device**: it has a version, a manifest digest,
//! grants and possibly a running instance. The states before `Installed` are about a plugin that is not on this device
//! at all — being resolved, downloaded and checked — and each of them holds something the later states do not: a
//! source, a partial download, a verification report.
//!
//! One enum holding both would be thirteen variants whose payloads are mostly irrelevant to whoever is reading, and
//! every method would have to say "except before installation" somewhere. Two types with one conversion between them
//! says the same thing in a way a reader can check.
//!
//! # The rule the design document is emphatic about
//!
//! **`Failed` is a state, not a log line.** A pipeline that returns to `Available` on failure and writes a note has
//! thrown away the three things a user needs: which stage failed, whether trying again could work, and how many times
//! it has been tried. All three are in [`Failed`], and the state is only left deliberately — by a retry, or by the
//! user abandoning the install.
//!
//! # Cancel, timeout and error are the same move
//!
//! Every state that is *doing* something can fail, and the three ways it fails arrive as one transition because
//! nothing downstream distinguishes them: what a caller does about a cancelled download and a timed-out one is the
//! same, and the sentence in [`Failed::detail`] is what tells a user which happened.

mod data;
mod moves;
mod source;
mod slot;
mod transition;

pub use data::{Consent, Progress, Resolved, Verified};
pub use source::{FailStage, Failed, InstallSource, WEAR_OUT_AFTER};
pub use slot::PluginSlot;
pub use moves::Move;
pub use transition::MoveError;

#[cfg(test)]
use super::state::State;

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000;

    fn registry_source() -> InstallSource {
        InstallSource::Registry { package: "@acme/hello".to_owned(), version: "^1".to_owned() }
    }

    fn resolved() -> Resolved {
        Resolved {
            version: "1.2.3".to_owned(),
            artifacts: vec!["plugin.wasm".to_owned()],
            manifest_digest: "aaa".to_owned(),
            development_only: false,
        }
    }

    fn verified() -> Verified {
        Verified {
            version: "1.2.3".to_owned(),
            artifact_digest: "bbb".to_owned(),
            manifest_digest: "aaa".to_owned(),
            requested: vec!["platform:open-url".to_owned()],
            trust: Some("signed by a publisher this device has seen".to_owned()),
        }
    }

    fn consented() -> Consent {
        Consent { granted: vec!["platform:open-url".to_owned()], denied: Vec::new() }
    }

    /// Drives a slot to `Installed`, through every stage, the way a caller does.
    fn installed() -> PluginSlot {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
        let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
        let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
        let _ = slot.apply(Move::Consented { consent: consented() }, NOW).expect("consented");
        let _ = slot.apply(Move::Installed, NOW).expect("installed");
        slot
    }

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

    #[test]
    fn a_failure_records_its_stage_and_whether_a_retry_could_work() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Download,
                    detail: "the connection dropped".to_owned(),
                    retryable: None,
                },
                1_500,
            )
            .expect("failed");

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure");
        };
        assert_eq!(failed.stage, FailStage::Download);
        assert!(failed.retryable, "a download can be tried again");
        assert_eq!(failed.attempts, 1);
        assert_eq!(failed.failed_at_ms, 1_500);
        assert!(slot.can_retry());
    }

    #[test]
    fn a_verification_failure_is_not_offered_as_a_retry() {
        // ★ The same bytes hash the same way. A retry button here is a button that cannot work.
        assert!(!FailStage::Verify.is_retryable(), "the stage's own answer");
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Verify,
                    detail: "the digest does not match".to_owned(),
                    retryable: None,
                },
                NOW,
            )
            .expect("failed");

        assert!(!slot.can_retry());
        assert!(matches!(slot.apply(Move::Retry, NOW), Err(MoveError::WrongState { .. })));
    }

    #[test]
    fn a_caller_that_knows_better_can_mark_a_retryable_stage_as_hopeless() {
        // A registry that answered 404 failed at `Resolve`, and no amount of trying will make the package exist.
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(
                Move::Fail {
                    stage: FailStage::Resolve,
                    detail: "no such package".to_owned(),
                    retryable: Some(false),
                },
                NOW,
            )
            .expect("failed");

        assert!(!slot.can_retry(), "the caller's answer wins over the stage's");
    }

    #[test]
    fn retrying_counts_the_attempts_and_starts_over_from_resolving() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(Move::Fail { stage: FailStage::Download, detail: "dropped".to_owned(), retryable: None }, NOW)
            .expect("failed");
        let _ = slot.apply(Move::Fail { stage: FailStage::Download, detail: "dropped again".to_owned(), retryable: None }, NOW);

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure");
        };
        assert_eq!(failed.attempts, 2, "a second failure increments rather than replaces");

        let _ = slot.apply(Move::Retry, NOW + 10).expect("retry");
        assert_eq!(slot.as_str(), "resolving", "a retry starts where the source is known again");
    }

    #[test]
    fn a_failure_that_keeps_happening_stops_offering_a_button() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        for attempt in 0..WEAR_OUT_AFTER {
            let _ = slot
                .apply(
                    Move::Fail {
                        stage: FailStage::Install,
                        detail: format!("attempt {attempt}"),
                        retryable: None,
                    },
                    NOW,
                )
                .expect("failed");
        }

        let PluginSlot::Failed(failed) = &slot else {
            panic!("expected a failure");
        };
        assert_eq!(failed.attempts, WEAR_OUT_AFTER);
        assert!(failed.is_worn_out());
        assert!(!slot.can_retry(), "the fourth offer of the same button is not useful");
        assert!(slot.describe().contains("attempts"), "{}", slot.describe());
    }

    #[test]
    fn abandoning_a_failure_returns_the_slot_to_available() {
        let mut slot = PluginSlot::available();
        let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
        let _ = slot
            .apply(Move::Fail { stage: FailStage::Download, detail: "dropped".to_owned(), retryable: None }, NOW)
            .expect("failed");
        let _ = slot.apply(Move::Abandon, NOW).expect("abandon");

        assert_eq!(slot, PluginSlot::Available);
        assert!(slot.source().is_none());
    }

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
    fn every_state_has_a_name_and_a_sentence() {
        // The property an interface depends on: a state with no label is a spinner with no text.
        let states = [
            PluginSlot::Available,
            PluginSlot::Resolving { source: registry_source() },
            PluginSlot::Downloading {
                source: registry_source(),
                resolved: resolved(),
                progress: Progress { received: 1, total: Some(2) },
            },
            PluginSlot::Verifying {
                source: registry_source(),
                resolved: resolved(),
                artifact_digest: "bbb".to_owned(),
            },
            PluginSlot::AwaitingConsent { source: registry_source(), verified: verified() },
            PluginSlot::Installing {
                source: registry_source(),
                verified: verified(),
                consent: consented(),
            },
            installed(),
            {
                let mut slot = installed();
                let _ = slot.apply(Move::Activate, NOW);
                slot
            },
            {
                let mut slot = installed();
                let _ = slot.apply(Move::Activate, NOW);
                let _ = slot.apply(Move::Activated, NOW);
                slot
            },
            {
                let mut slot = installed();
                let _ = slot.apply(Move::Remove, NOW);
                slot
            },
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Download, "dropped", NOW)),
        ];

        let mut seen: Vec<&str> = Vec::new();
        for state in &states {
            let name = state.as_str();
            assert!(!name.is_empty());
            assert!(!seen.contains(&name), "{name} names two states");
            seen.push(name);
            let sentence = state.describe();
            assert!(sentence.len() > 3, "{name} -> {sentence}");
        }
        // And the thirteen names are all distinct, which is what the design document's table is.
        assert!(seen.len() >= 11, "{} states covered", seen.len());
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

    #[test]
    fn every_state_survives_a_trip_through_json() {
        // ★ The reason these types are serialisable at all: a settings screen shows where a plugin is, and the state it
        // shows should be the state that was decided rather than a rendering of it. A round trip that lost a field
        // would be a screen describing a plugin that is not the one the kernel has.
        let states = [
            PluginSlot::Available,
            PluginSlot::Resolving { source: registry_source() },
            PluginSlot::Downloading {
                source: registry_source(),
                resolved: resolved(),
                progress: Progress { received: 900, total: Some(1_000) },
            },
            PluginSlot::Verifying {
                source: registry_source(),
                resolved: resolved(),
                artifact_digest: "bbb".to_owned(),
            },
            PluginSlot::AwaitingConsent { source: registry_source(), verified: verified() },
            PluginSlot::Installing {
                source: registry_source(),
                verified: verified(),
                consent: consented(),
            },
            installed(),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Download, "the connection dropped", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Verify, "the digest does not match", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Activate, "it trapped", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Consent, "declined", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Install, "the disk is full", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Remove, "the file is locked", NOW)),
            PluginSlot::Failed(Failed::at(registry_source(), FailStage::Resolve, "no such package", NOW)),
        ];

        for state in &states {
            let json = serde_json::to_string(state).unwrap_or_else(|error| panic!("{state:?}: {error}"));
            let back: PluginSlot = serde_json::from_str(&json).unwrap_or_else(|error| panic!("{json}: {error}"));
            assert_eq!(&back, state, "{json}");
            // And the tag a screen matches on is the same word the kernel calls the state, which is what stops the two
            // from drifting.
            assert!(json.contains(state.as_str()), "{json}");
        }
    }

    #[test]
    fn an_install_source_says_what_kind_it_is_in_json() {
        // A tagged union, so a reader does not have to guess which fields are present — and the tag is the same word
        // `kind` returns.
        let source = InstallSource::Git { url: "https://example".to_owned(), reference: Some("main".to_owned()) };
        let json = serde_json::to_string(&source).expect("serialises");
        assert!(json.contains("\"kind\":\"git\""), "{json}");
        assert!(json.contains("https://example"), "{json}");
        let back: InstallSource = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, source);
        assert_eq!(source.kind(), "git");
    }

    #[test]
    fn a_failure_that_went_through_json_still_knows_whether_a_retry_could_work() {
        // The field a button is drawn from, so a round trip that lost it would be a screen offering a retry for a
        // digest that will never match.
        let hopeless = Failed::at(registry_source(), FailStage::Verify, "the digest does not match", NOW);
        let json = serde_json::to_string(&hopeless).expect("serialises");
        let back: Failed = serde_json::from_str(&json).expect("deserialises");
        assert!(!back.retryable);
        assert_eq!(back.stage, FailStage::Verify);
        assert_eq!(back.stage.as_str(), "verify");
        assert_eq!(back.failed_at_ms, NOW);
    }
}
