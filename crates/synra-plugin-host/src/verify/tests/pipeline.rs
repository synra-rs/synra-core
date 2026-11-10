use synra_plugin_api::publisher::PublisherTrustStore;
use super::super::{Candidate, HostFacts, Stage, Verdict, VerifyError, host_surface, host_world, verify};
use super::Fixture;

#[test]
fn a_good_package_passes_every_check_in_order() {
    let fixture = Fixture::new();
    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");

    assert!(report.is_acceptable());
    assert!(report.warnings().is_empty());
    assert!(report.refusal().is_none());
    assert!(report.stopped_at().is_none());
    assert_eq!(report.steps.len(), Stage::ALL.len(), "every step ran");
    // And they ran in the order the design document gives, which is the argument the pipeline makes.
    let ran: Vec<Stage> = report.steps.iter().map(|step| step.stage).collect();
    assert_eq!(ran, Stage::ALL.to_vec());
    assert!(report.describe().contains("11 checks"), "{}", report.describe());
}

#[test]
fn every_stage_has_a_name_and_a_number() {
    // The number is what a report shows and what a metric label uses, so an unnumbered stage would be one with no way
    // to refer to it.
    let mut seen: Vec<&str> = Vec::new();
    for (index, stage) in Stage::ALL.iter().enumerate() {
        assert_eq!(stage.number(), index + 1, "{stage:?}");
        assert!(!seen.contains(&stage.as_str()), "{stage:?} names two stages");
        seen.push(stage.as_str());
    }
    assert_eq!(Stage::ALL.len(), 11, "the design document lists eleven");
}

// ── Stage 1 · the digest ──────────────────────────────────────────────────────────────────────────

#[test]
fn an_artifact_that_is_not_the_one_declared_stops_at_the_digest() {
    let mut fixture = Fixture::new();
    fixture.digest = "sha256-abc".to_owned();
    let candidate = Candidate { actual_digest: "sha256-other", ..fixture.candidate(None, false) };

    match verify(&candidate, &PublisherTrustStore::new()) {
        Err((stage, VerifyError::DigestMismatch)) => assert_eq!(stage, Stage::Digest),
        other => panic!("expected a digest refusal, got {other:?}"),
    }
}

#[test]
fn a_source_that_declared_no_digest_is_not_a_mismatch() {
    // A local build an author is testing has nothing to compare against, and treating "no claim" as "the claim was
    // wrong" would make local plugins uninstallable.
    let fixture = Fixture::new();
    let candidate = Candidate { declared_digest: None, ..fixture.candidate(None, false) };
    let report = verify(&candidate, &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
    assert!(report.steps.first().expect("a step").detail.contains("no digest"));
}

#[test]
fn an_empty_inventory_stops_at_the_archive_step() {
    let mut fixture = Fixture::new();
    fixture.artifacts.clear();
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::ArchiveTooLarge { .. })) => assert_eq!(stage, Stage::ArchiveLimits),
        other => panic!("expected an archive refusal, got {other:?}"),
    }
}

#[test]
fn a_refusal_names_the_stage_and_the_step_it_stopped_at() {
    // What a caller reports: "refused at manifest-schema" is actionable; "invalid package" is not.
    let mut fixture = Fixture::new();
    fixture.manifest = "{}".to_owned();
    let Err((stage, error)) = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) else {
        panic!("a manifest of `{{}}` must be refused");
    };
    assert_eq!(stage, Stage::ManifestSchema);
    assert_eq!(stage.number(), 4);
    assert!(!error.to_string().is_empty());
}

#[test]
fn the_host_world_is_the_one_the_contract_declares() {
    // Read from the generated table, so a contract version bump cannot leave the compatibility check behind.
    assert_eq!(host_world(), format!("{}@{}", host_surface::PACKAGE, host_surface::PACKAGE_VERSION));
    assert!(HostFacts::desktop().wit == host_world());
    assert!(HostFacts::headless().actions.is_empty());
    assert!(!HostFacts::headless().has_network);
}

#[test]
fn every_refusal_and_verdict_explains_itself() {
    let refusals = [
        VerifyError::DigestMismatch,
        VerifyError::BadSignature { reason: "the bytes changed".to_owned() },
        VerifyError::Unsigned,
        VerifyError::UnknownCapability { capability: "storag:local:read".to_owned() },
        VerifyError::WitIncompatible { required: "a".to_owned(), provided: "b".to_owned() },
        VerifyError::UndeclaredImport { import: "x".to_owned() },
        VerifyError::ForbiddenImport { import: "y".to_owned() },
        VerifyError::DependencyCycle { cycle: vec!["a".to_owned(), "b".to_owned(), "a".to_owned()] },
        VerifyError::ArchiveTooLarge { detail: "the artifact is empty".to_owned() },
        VerifyError::PlatformUnsupported { needed: "z".to_owned() },
    ];
    for refusal in &refusals {
        let sentence = refusal.to_string();
        assert!(sentence.len() > 15, "{refusal:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
        assert!(!sentence.contains('}'), "{sentence}");
    }
    // The two that name something name it, which is what an author needs.
    assert!(refusals[7].to_string().contains("a -> b -> a"), "{}", refusals[7]);
    assert!(refusals[2].to_string().contains("unsigned"));

    for verdict in [Verdict::Pass, Verdict::Warn, Verdict::Fail] {
        assert!(!verdict.as_str().is_empty());
    }
}
