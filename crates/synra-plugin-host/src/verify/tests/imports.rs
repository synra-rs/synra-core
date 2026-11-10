use synra_plugin_api::publisher::PublisherTrustStore;
use super::super::{Stage, VerifyError, verify};
use super::{Fixture, importing_component, manifest_json};

#[test]
fn an_import_no_declared_capability_covers_stops_at_that_step() {
    // The plugin calls `storage-set`, which needs `storage:local:write`, and its manifest declares only `log:*`.
    let mut fixture = Fixture::new();
    fixture.artifact = synra_testkit::plugin_events::EventPlugin::receiver(None)
        .expect("a real importing component")
        .wasm;
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
    fixture.artifact = synra_testkit::plugin_events::EventPlugin::receiver(None)
        .expect("a real importing component")
        .wasm;
    let report =
        verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
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
        fixture.artifact = importing_component(import);
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
    fixture.artifact = synra_testkit::plugin_events::EventPlugin::receiver(None)
        .expect("a real importing component")
        .wasm;

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
    fixture.artifact = importing_component("synra:plugin/host#env-sdk-version");
    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}
