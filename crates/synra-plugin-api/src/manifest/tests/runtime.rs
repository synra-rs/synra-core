use super::super::error::ManifestError;
use super::super::types::ManifestContext;
use super::{MINIMAL, minimal, parse};

#[test]
fn a_plugin_must_declare_a_runtime() {
    let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": {}",
        );
    let manifest = parse(&text);
    assert!(matches!(
        manifest.validate(&ManifestContext::default()),
        Err(ManifestError::MissingHeadless)
    ));
}

#[test]
fn a_ui_only_plugin_is_refused() {
    let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
        );
    let manifest = parse(&text);
    assert!(manifest.has_ui());
    assert!(!manifest.is_headless());
    assert_eq!(
        manifest.validate(&ManifestContext::default()),
        Err(ManifestError::MissingHeadless)
    );
}

#[test]
fn a_hybrid_plugin_is_recognised() {
    let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \
                \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \
                \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
        );
    let manifest = parse(&text);
    assert!(manifest.is_hybrid());
}

#[test]
fn a_missing_artifact_is_reported_when_the_package_is_known() {
    let context = ManifestContext {
        present_artifacts: Some(vec!["dist/other.wasm".to_owned()]),
        ..ManifestContext::default()
    };
    match minimal().validate(&context) {
        Err(ManifestError::MissingArtifact { kind, path }) => {
            assert_eq!(kind, "headless");
            assert_eq!(path, "dist/plugin.wasm");
        }
        other => panic!("expected a missing artifact, got {other:?}"),
    }
}

#[test]
fn a_present_artifact_passes_that_check() {
    let context = ManifestContext {
        present_artifacts: Some(vec!["dist/plugin.wasm".to_owned()]),
        ..ManifestContext::default()
    };
    assert_eq!(minimal().validate(&context), Ok(()));
}

#[test]
fn an_empty_ui_entry_is_refused() {
    let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"  \" } }",
        );
    assert!(parse(&text).validate(&ManifestContext::default()).is_err());
}
