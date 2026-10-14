//! The eleven checks, driven with a package for every way one can be refused.
//!
//! A pipeline test that only ever fed a good package would pass against one that ran a single check and returned
//! `Pass` eleven times. So every stage has a case that must stop there, and the assertion is *which* stage — because
//! "it was refused" is not the answer an author needs.

use ed25519_dalek::{Signer as _, SigningKey};
use synra_plugin_api::publisher::{
    ALGORITHM, Fingerprint, PublisherTrustStore, SIGNATURE_VERSION, SigningSubject,
};

use super::*;

/// A publisher's key, derived from a byte so a test can name it.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A manifest with the given capabilities.
fn manifest_json(capabilities: &[&str]) -> String {
    let declared: Vec<serde_json::Value> = capabilities
        .iter()
        .map(|capability| serde_json::json!({ "cap": capability }))
        .collect();
    serde_json::json!({
        "id": "@acme/hello",
        "version": "1.2.3",
        "title": "Hello",
        "publisher": { "id": "acme" },
        "sdk": { "min": "1.0.0" },
        "wit": host_world(),
        "capabilities": declared,
        "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
    })
    .to_string()
}

/// A candidate that passes every check, which each test then breaks in one place.
struct Fixture {
    manifest: String,
    artifact: Vec<u8>,
    digest: String,
    imports: Vec<String>,
    graph: DependencyGraph,
}

impl Fixture {
    fn new() -> Self {
        Self {
            manifest: manifest_json(&["log:*"]),
            artifact: b"\0asm\x01\0\0\0".to_vec(),
            digest: "sha256-abc".to_owned(),
            imports: Vec::new(),
            graph: DependencyGraph::new(),
        }
    }

    /// A candidate borrowing the fixture, with an optional signature.
    fn candidate<'a>(&'a self, signature: Option<&'a str>, required: bool) -> Candidate<'a> {
        Candidate {
            manifest_json: &self.manifest,
            manifest: None,
            artifact: &self.artifact,
            declared_digest: Some(&self.digest),
            actual_digest: &self.digest,
            signature,
            signature_required: required,
            imports: &self.imports,
            dependencies: &self.graph,
            host: HostFacts::desktop(),
        }
    }
}

/// A signature document over a subject, signed by a key.
fn signed(subject: &SigningSubject, publisher_id: &str, seed: u8) -> String {
    let signing = key(seed);
    let signature = signing.sign(&subject.canonical_bytes());
    serde_json::to_string(&serde_json::json!({
        "version": SIGNATURE_VERSION,
        "publisher": { "id": publisher_id },
        "algorithm": ALGORITHM,
        "signedAt": "unix-ms:1",
        "pubkey": base64_of(signing.verifying_key().as_bytes()),
        "subject": { "manifest": subject.manifest, "artifacts": subject.artifacts },
        "signature": base64_of(&signature.to_bytes()),
    }))
    .expect("a document")
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn subject() -> SigningSubject {
    let mut artifacts = synra_plugin_api::publisher::Digests::new();
    artifacts.insert("plugin.wasm", "sha256-abc");
    SigningSubject { manifest: "sha256-manifest".to_owned(), artifacts }
}

// ── The whole path ────────────────────────────────────────────────────────────────────────────────

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

// ── Stages 2 and 3 · the signature and the publisher ──────────────────────────────────────────────

#[test]
fn an_unsigned_package_is_refused_when_the_host_requires_one() {
    let fixture = Fixture::new();
    match verify(&fixture.candidate(None, true), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::Unsigned)) => assert_eq!(stage, Stage::Signature),
        other => panic!("expected an unsigned refusal, got {other:?}"),
    }
}

#[test]
fn a_tampered_subject_stops_at_the_signature() {
    // The document is valid JSON and the key is a key; what does not hold is the signature over the bytes.
    let fixture = Fixture::new();
    let mut document: serde_json::Value = serde_json::from_str(&signed(&subject(), "acme", 7)).expect("valid JSON");
    document["subject"]["artifacts"]["plugin.wasm"] = serde_json::json!("sha256-tampered");
    let text = document.to_string();

    match verify(&fixture.candidate(Some(&text), true), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::BadSignature { .. })) => assert_eq!(stage, Stage::Signature),
        other => panic!("expected a signature refusal, got {other:?}"),
    }
}

#[test]
fn a_revoked_publisher_stops_at_the_trust_step_with_the_reason() {
    // ★ A refusal and not a warning: a revocation is a decision already made, and a user cannot consent past it.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let mut store = PublisherTrustStore::new();
    store.revoke(Fingerprint::of(&key(7).verifying_key()), "malicious code");

    match verify(&fixture.candidate(Some(&text), true), &store) {
        Err((stage, VerifyError::UntrustedPublisher { why })) => {
            assert_eq!(stage, Stage::PublisherTrust);
            assert!(why.to_string().contains("malicious code"), "{why}");
        }
        other => panic!("expected a trust refusal, got {other:?}"),
    }
}

#[test]
fn an_unknown_publisher_passes_and_is_reported_so_the_interface_can_ask() {
    // ★ The pipeline does not decide who the user trusts: it reports what it found. A pipeline that failed here would
    // make the first install from anybody impossible.
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let report = verify(&fixture.candidate(Some(&text), true), &PublisherTrustStore::new()).expect("a report");

    assert!(report.is_acceptable());
    assert_eq!(report.trust, Some(PluginTrust::UnknownPublisher));
    assert_eq!(report.fingerprint, Some(Fingerprint::of(&key(7).verifying_key())));
    let trust_step = report
        .steps
        .iter()
        .find(|step| step.stage == Stage::PublisherTrust)
        .expect("a trust step");
    assert!(trust_step.detail.contains("asked"), "{}", trust_step.detail);
}

#[test]
fn a_publisher_this_device_trusts_is_reported_as_trusted() {
    let fixture = Fixture::new();
    let text = signed(&subject(), "acme", 7);
    let mut store = PublisherTrustStore::new();
    store.trust("acme", Fingerprint::of(&key(7).verifying_key()));

    let report = verify(&fixture.candidate(Some(&text), true), &store).expect("a report");
    assert_eq!(report.trust, Some(PluginTrust::TrustedPublisher));
    assert!(report.trust.expect("a level").is_trusted());
}

// ── Stage 4 · the manifest ────────────────────────────────────────────────────────────────────────

#[test]
fn a_manifest_that_is_not_json_stops_at_the_schema() {
    let mut fixture = Fixture::new();
    fixture.manifest = "not json".to_owned();
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::InvalidManifest { .. })) => assert_eq!(stage, Stage::ManifestSchema),
        other => panic!("expected a schema refusal, got {other:?}"),
    }
}

#[test]
fn a_manifest_whose_fields_are_invalid_stops_at_the_schema() {
    // An unscoped plugin id, which the manifest's own rules refuse. The reason names the field, because "invalid
    // manifest" leaves an author with a file to re-read.
    let mut fixture = Fixture::new();
    fixture.manifest = fixture.manifest.replace("@acme/hello", "hello");
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::InvalidManifest { reason })) => {
            assert_eq!(stage, Stage::ManifestSchema);
            assert!(!reason.is_empty());
        }
        other => panic!("expected a schema refusal, got {other:?}"),
    }
}

// ── Stage 5 · the capability syntax ───────────────────────────────────────────────────────────────

#[test]
fn a_capability_whose_domain_is_unknown_is_refused_by_the_manifest_itself() {
    // ★ The better message wins: `storag:local:read` is refused by the manifest's own validator, which names the
    // domain, rather than by the syntax backstop below it.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["storag:local:read"]);
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::InvalidManifest { reason })) => {
            assert_eq!(stage, Stage::ManifestSchema);
            assert!(reason.contains("storag"), "{reason}");
        }
        other => panic!("expected a schema refusal, got {other:?}"),
    }
}

#[test]
fn a_well_formed_capability_no_host_function_needs_stops_at_the_syntax_step() {
    // The backstop's own case: **two** capabilities, one of which the manifest's runtime rules accept. `log:*` is on
    // the runtime allow-list and a headless plugin may hold it, so the manifest passes — and `device:listx` is a real
    // domain carrying a name no host function acts on, which is the mistake that would otherwise install a plugin
    // holding a permission nothing ever checks.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["device:listx", "log:*"]);
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::UnknownCapability { capability })) => {
            assert_eq!(stage, Stage::CapabilitySyntax);
            assert_eq!(capability, "device:listx");
        }
        other => panic!("expected a capability refusal, got {other:?}"),
    }
}

// ── Stage 6 · WIT compatibility ───────────────────────────────────────────────────────────────────

#[test]
fn a_plugin_built_for_another_world_stops_at_compatibility() {
    let mut fixture = Fixture::new();
    fixture.manifest = fixture.manifest.replace(&host_world(), "synra:plugin@9.0.0");
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::WitIncompatible { required, provided })) => {
            assert_eq!(stage, Stage::WitCompatibility);
            assert_eq!(required, "synra:plugin@9.0.0");
            assert_eq!(provided, host_world());
        }
        // The manifest's own version check may refuse it first, which is also a correct answer and a better message.
        Err((stage, VerifyError::InvalidManifest { .. })) => assert_eq!(stage, Stage::ManifestSchema),
        other => panic!("expected a compatibility refusal, got {other:?}"),
    }
}

// ── Stage 7 · imports within capabilities ─────────────────────────────────────────────────────────

#[test]
fn an_import_no_declared_capability_covers_stops_at_that_step() {
    // The plugin calls `storage-set`, which needs `storage:local:write`, and its manifest declares only `log:*`.
    let mut fixture = Fixture::new();
    fixture.imports = vec!["synra:plugin/host#storage-set".to_owned()];
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::UndeclaredImport { import })) => {
            assert_eq!(stage, Stage::ImportsWithinCapabilities);
            // The import is named rather than the capability: an author who read `capability denied` and a capability
            // string has to work out which call needed it.
            assert_eq!(import, "synra:plugin/host#storage-set");
        }
        other => panic!("expected an import refusal, got {other:?}"),
    }
}

#[test]
fn an_import_the_declared_capability_covers_passes() {
    // The positive case, so the check is not one that refuses everything.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["storage:local:write"]);
    fixture.imports = vec!["synra:plugin/host#storage-set".to_owned()];
    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}

// ── Stage 8 · forbidden imports ───────────────────────────────────────────────────────────────────

#[test]
fn an_import_the_host_does_not_provide_stops_at_that_step() {
    // ★ An artifact importing something outside the contract — `wasi:filesystem`, or a function from a newer SDK. The
    // host does not provide it, and the report says exactly that rather than sending an author to their manifest.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&[]);
    for import in [
        "synra:plugin/host#env-telepathy",
        "wasi:filesystem/types@0.2.0",
        "synra:plugin/host#teleport",
    ] {
        fixture.imports = vec![import.to_owned()];
        match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
            Err((stage, VerifyError::ForbiddenImport { import: named })) => {
                assert_eq!(stage, Stage::NoForbiddenImports);
                assert_eq!(named, import);
            }
            other => panic!("{import} -> {other:?}"),
        }
    }
}

#[test]
fn an_import_this_host_provides_but_the_manifest_does_not_cover_stops_at_the_coverage_step() {
    // The other half of the pair: the host has the function, and the plugin did not ask for the permission it needs.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["log:*"]);
    fixture.imports = vec!["synra:plugin/host#storage-set".to_owned()];

    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::UndeclaredImport { import })) => {
            assert_eq!(stage, Stage::ImportsWithinCapabilities);
            assert_eq!(import, "synra:plugin/host#storage-set");
        }
        other => panic!("expected an import refusal, got {other:?}"),
    }
}

#[test]
fn an_ungated_import_the_host_does_provide_passes() {
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&[]);
    fixture.imports = vec!["synra:plugin/host#env-sdk-version".to_owned()];
    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}

// ── Stage 9 · the dependency graph ────────────────────────────────────────────────────────────────

#[test]
fn a_dependency_cycle_stops_at_that_step_and_names_the_cycle() {
    // ★ The check a single plugin's own edges cannot make: a cycle is a property of the graph.
    let mut fixture = Fixture::new();
    let mut graph = DependencyGraph::new();
    graph.set("@acme/hello".to_owned(), vec!["@acme/other".to_owned()]);
    graph.set("@acme/other".to_owned(), vec!["@acme/hello".to_owned()]);
    fixture.graph = graph;

    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::DependencyCycle { cycle })) => {
            assert_eq!(stage, Stage::DependencyAcyclic);
            // The path closes on itself, which is what makes it readable: `a -> b -> a`.
            assert_eq!(cycle.first(), cycle.last(), "{cycle:?}");
            assert!(cycle.len() >= 2, "{cycle:?}");
        }
        other => panic!("expected a cycle refusal, got {other:?}"),
    }
}

#[test]
fn a_graph_without_a_cycle_passes() {
    let mut fixture = Fixture::new();
    let mut graph = DependencyGraph::new();
    graph.set("@acme/hello".to_owned(), vec!["@acme/a".to_owned(), "@acme/b".to_owned()]);
    graph.set("@acme/a".to_owned(), vec!["@acme/c".to_owned()]);
    graph.set("@acme/b".to_owned(), vec!["@acme/c".to_owned()]);
    graph.set("@acme/c".to_owned(), Vec::new());
    fixture.graph = graph;

    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}

#[test]
fn a_cycle_this_plugin_is_not_part_of_is_not_its_problem() {
    // The question is "would installing this loop". A cycle among plugins it does not depend on would not.
    let mut fixture = Fixture::new();
    let mut graph = DependencyGraph::new();
    graph.set("@acme/hello".to_owned(), vec!["@acme/good".to_owned()]);
    graph.set("@acme/good".to_owned(), Vec::new());
    graph.set("@acme/x".to_owned(), vec!["@acme/y".to_owned()]);
    graph.set("@acme/y".to_owned(), vec!["@acme/x".to_owned()]);
    fixture.graph = graph;

    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}

#[test]
fn a_plugin_that_depends_on_itself_is_a_cycle() {
    let graph: DependencyGraph =
        [("@acme/hello".to_owned(), vec!["@acme/hello".to_owned()])].into_iter().collect();
    assert_eq!(graph.cycle_from("@acme/hello"), Some(vec!["@acme/hello".to_owned(), "@acme/hello".to_owned()]));
}

#[test]
fn a_deep_chain_does_not_overflow_a_stack() {
    // The search is iterative rather than recursive because a dependency graph is data from a package, and a deep one
    // would be a stack overflow in the process checking whether the package is safe to run.
    let mut graph = DependencyGraph::new();
    for index in 0..20_000 {
        graph.set(format!("@acme/p{index}"), vec![format!("@acme/p{}", index + 1)]);
    }
    graph.set("@acme/p20000".to_owned(), Vec::new());
    assert_eq!(graph.cycle_from("@acme/p0"), None);
}

// ── Stage 10 · the archive ────────────────────────────────────────────────────────────────────────

#[test]
fn an_empty_artifact_stops_at_the_archive_step() {
    let mut fixture = Fixture::new();
    fixture.artifact = Vec::new();
    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::ArchiveTooLarge { .. })) => assert_eq!(stage, Stage::ArchiveLimits),
        other => panic!("expected an archive refusal, got {other:?}"),
    }
}

// ── Stage 11 · the platform ───────────────────────────────────────────────────────────────────────

#[test]
fn a_plugin_needing_something_this_host_cannot_do_warns_rather_than_failing() {
    // ★ A warning, because the package is valid: its notification button will not work on this machine and will work
    // on another. Refusing it would make a plugin uninstallable on the device that cannot do one of the things it
    // offers.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["platform:simulate-keys"]);
    let facts = HostFacts { actions: Vec::new(), ..HostFacts::desktop() };
    let candidate = Candidate { host: facts, ..fixture.candidate(None, false) };

    let report = verify(&candidate, &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable(), "a warning is not a refusal");
    // The warnings are read off the steps rather than through a temporary vector, which would be dropped while the
    // reference into it is still held.
    let warnings: Vec<&Step> = report.steps.iter().filter(|step| step.verdict == Verdict::Warn).collect();
    assert_eq!(warnings.len(), 1);
    let warning = warnings.first().expect("a warning");
    assert_eq!(warning.stage, Stage::PlatformApplicability);
    assert!(warning.detail.contains("simulate-keys"), "{}", warning.detail);
    assert!(report.describe().contains("warning"), "{}", report.describe());
}

#[test]
fn a_headless_host_warns_about_the_platform_actions_it_has_none_of() {
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["platform:open-url"]);
    let candidate = Candidate { host: HostFacts::headless(), ..fixture.candidate(None, false) };

    let report = verify(&candidate, &PublisherTrustStore::new()).expect("a report");
    assert_eq!(report.warnings().len(), 1);
    assert!(report.warnings().first().expect("a warning").detail.contains("platform:open-url"));
}

#[test]
fn a_plugin_whose_capabilities_the_host_has_does_not_warn() {
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["platform:open-url"]);
    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.warnings().is_empty());
    assert!(report.describe().contains("all 11"), "{}", report.describe());
}

// ── The report ────────────────────────────────────────────────────────────────────────────────────

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
fn a_signature_document_that_is_not_one_stops_at_the_signature() {
    let fixture = Fixture::new();
    for text in ["", "not json", "{}"] {
        match verify(&fixture.candidate(Some(text), true), &PublisherTrustStore::new()) {
            Err((stage, VerifyError::BadSignature { .. })) => assert_eq!(stage, Stage::Signature),
            other => panic!("{text} -> {other:?}"),
        }
    }
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
