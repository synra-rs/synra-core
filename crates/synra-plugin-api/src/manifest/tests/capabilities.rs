use super::super::error::ManifestError;
use super::super::types::ManifestContext;
use super::{MINIMAL, parse};

#[test]
fn a_malformed_capability_is_refused_and_names_itself() {
    let text = MINIMAL.replace("\"log:*\"", "\"not a capability\"");
    let manifest = parse(&text);
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::BadCapability { cap, .. }) => assert_eq!(cap, "not a capability"),
        other => panic!("expected a capability error, got {other:?}"),
    }
}

#[test]
fn a_headless_plugin_may_not_declare_ui_capabilities() {
    // A `ui:*` grant on a headless plugin is one the user approves at install time and that nothing can
    // ever exercise: the consent screen said something untrue.
    let text = MINIMAL.replace(
        "[{ \"cap\": \"log:*\" }]",
        "[{ \"cap\": \"log:*\" }, { \"cap\": \"ui:page\" }]",
    );
    let manifest = parse(&text);
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::UnusableCapability { cap, kind }) => {
            assert_eq!(cap, "ui:page");
            assert_eq!(kind, "headless");
        }
        other => panic!("expected an unusable capability, got {other:?}"),
    }
}

#[test]
fn a_hybrid_plugin_may_declare_ui_capabilities() {
    let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
            )
            .replace(
                "[{ \"cap\": \"log:*\" }]",
                "[{ \"cap\": \"log:*\" }, { \"cap\": \"ui:page\" }]",
            );
    assert_eq!(parse(&text).validate(&ManifestContext::default()), Ok(()));
}
