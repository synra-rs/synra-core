use synra_plugin_api::publisher::PublisherTrustStore;
use super::super::{Stage, VerifyError, host_world, verify};
use super::{Fixture, manifest_json};

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
