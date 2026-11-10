use super::super::error::ManifestError;
use super::super::types::ManifestContext;
use super::{MINIMAL, parse};

#[test]
fn a_declared_pages_list_on_a_headless_plugin_is_refused() {
    // There is no interface to put a page in.
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"pages\": [{ \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }]",
    );
    assert!(parse(&text).validate(&ManifestContext::default()).is_err());
}

#[test]
fn a_duplicate_page_key_is_refused() {
    let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
            )
            .replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                "\"capabilities\": [{ \"cap\": \"log:*\" }], \"pages\": [\
                 { \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }, \
                 { \"key\": \"home\", \"title\": \"Again\", \"path\": \"/again\" }]",
            );
    let manifest = parse(&text);
    assert!(matches!(
        manifest.validate(&ManifestContext::default()),
        Err(ManifestError::DuplicatePageKey { key }) if key == "home"
    ));
}

#[test]
fn a_default_page_that_is_not_declared_is_refused() {
    let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\", \
                 \"defaultPage\": \"missing\" } }",
            )
            .replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                "\"capabilities\": [{ \"cap\": \"log:*\" }], \
                 \"pages\": [{ \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }]",
            );
    assert!(parse(&text).validate(&ManifestContext::default()).is_err());
}
