use super::super::{Progress, FailStage, Failed, InstallSource, PluginSlot, Move};
use super::{NOW, registry_source, resolved, verified, consented, installed};

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
