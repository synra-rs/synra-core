use super::super::error::ManifestError;
use super::super::types::{Manifest, ManifestContext, MANIFEST_SCHEMA};
use super::{MINIMAL, minimal, parse};

#[test]
fn a_minimal_manifest_parses_and_validates() {
    let manifest = minimal();
    assert_eq!(manifest.id.as_str(), "@synra-plugin/chat");
    assert_eq!(manifest.title, "Chat");
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
    assert!(manifest.is_headless());
    assert!(!manifest.has_ui());
    assert!(!manifest.is_hybrid());
}

#[test]
fn a_legacy_capability_spelling_is_corrected_when_the_manifest_is_read() {
    // ★ The contract has always checked `platform:read-clipboard`, and this workspace's documentation used
    // `platform:clipboard:read`. A manifest written from the documentation therefore asked for a permission that
    // could never authorise anything. Correcting at the boundary means everything after this point — the consent
    // prompt, the grant row, the gate — sees one name.
    let manifest = parse(&MINIMAL.replace(r#""log:*""#, r#""platform:clipboard:read""#));

    assert_eq!(manifest.capabilities[0].cap, "platform:read-clipboard");

    // And an ordinary capability is untouched: this is a correction table, not a rewriting of the vocabulary.
    let untouched = parse(&MINIMAL.replace(r#""log:*""#, r#""network:fetch:api.example.com""#));
    assert_eq!(
        untouched.capabilities[0].cap,
        "network:fetch:api.example.com"
    );
}

#[test]
fn the_schema_field_is_normalised_and_an_unknown_one_is_refused() {
    let manifest = minimal();
    assert_eq!(manifest.schema.as_deref(), Some(MANIFEST_SCHEMA));

    // A manifest naming a schema this build does not know may have fields whose meaning changed, and the
    // unknown-field rule would not catch a field that kept its name.
    let wrong = MINIMAL.replace(
        "\"id\":",
        "\"$schema\": \"https://example.com/v9.json\", \"id\":",
    );
    assert!(matches!(
        Manifest::from_json(&wrong),
        Err(ManifestError::Malformed(_))
    ));
}

#[test]
fn an_unknown_field_is_refused() {
    // A field the host silently ignores is a field whose author believes it does something.
    let text = MINIMAL.replace(
        "\"title\": \"Chat\",",
        "\"title\": \"Chat\", \"mystery\": true,",
    );
    assert!(matches!(
        Manifest::from_json(&text),
        Err(ManifestError::Malformed(_))
    ));
}

#[test]
fn a_missing_required_field_is_refused() {
    for field in [
        "\"id\": \"@synra-plugin/chat\",",
        "\"version\": \"1.0.0\",",
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
    ] {
        let text = MINIMAL.replace(field, "");
        assert!(
            Manifest::from_json(&text).is_err(),
            "removing {field} should fail"
        );
    }
}

#[test]
fn capabilities_may_be_an_empty_list_but_the_field_must_be_present() {
    // A missing field and an empty list are different statements — "the author forgot" and "this plugin
    // needs nothing" — and the loader has to be able to tell them apart.
    let empty = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": []",
    );
    let manifest = parse(&empty);
    assert!(manifest.capabilities.is_empty());
    assert!(manifest.capability_set().expect("compiles").is_empty());

    let missing = MINIMAL.replace(",\n        \"capabilities\": [{ \"cap\": \"log:*\" }]", "");
    assert!(Manifest::from_json(&missing).is_err());
}

#[test]
fn optional_arrays_are_absent_rather_than_empty() {
    let manifest = minimal();
    assert!(manifest.actions.is_empty());
    assert!(manifest.events.is_empty());
    assert!(manifest.handles.is_empty());
    assert!(manifest.pages.is_empty());
    assert!(manifest.network.is_none());

    // And a round trip does not turn them into empty arrays, so two manifests of the same plugin compare
    // equal.
    let json = serde_json::to_string(&manifest).expect("serialises");
    assert!(!json.contains("\"actions\""), "{json}");
}
