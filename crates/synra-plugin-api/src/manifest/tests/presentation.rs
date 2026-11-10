use super::super::error::ManifestError;
use super::super::types::{ManifestContext, MAX_TITLE_LEN};
use super::{MINIMAL, minimal, parse};

#[test]
fn action_names_are_validated_when_a_manifest_is_admitted() {
    for (name, allowed) in [
        ("format-date", true),
        ("*", false),
        ("a:b", false),
        ("a/b", false),
        ("中文", false),
    ] {
        let mut document: serde_json::Value = serde_json::from_str(MINIMAL).expect("fixture");
        document["actions"] = serde_json::json!([{ "name": name }]);
        let result = parse(&document.to_string()).validate(&ManifestContext::default());
        assert_eq!(result.is_ok(), allowed, "{name}: {result:?}");
    }
}

#[test]
fn a_duplicate_action_name_is_refused() {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \"actions\": [\
             { \"name\": \"send\" }, { \"name\": \"send\" }]",
    );
    let manifest = parse(&text);
    assert!(matches!(
        manifest.validate(&ManifestContext::default()),
        Err(ManifestError::DuplicateName { kind: "action", .. })
    ));
}

#[test]
fn an_action_with_an_empty_name_is_refused() {
    let text = MINIMAL.replace(
        "\"capabilities\": [{ \"cap\": \"log:*\" }]",
        "\"capabilities\": [{ \"cap\": \"log:*\" }], \"actions\": [{ \"name\": \"\" }]",
    );
    assert!(parse(&text).validate(&ManifestContext::default()).is_err());
}

#[test]
fn length_limits_are_enforced_on_what_the_interface_draws() {
    // A title of a thousand characters pushes everything else off the screen.
    let long = "x".repeat(MAX_TITLE_LEN + 1);
    let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{long}\""));
    let manifest = parse(&text);
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::TooLong { field, len, max }) => {
            assert_eq!(field, "title");
            assert_eq!(len, MAX_TITLE_LEN + 1);
            assert_eq!(max, MAX_TITLE_LEN);
        }
        other => panic!("expected a length refusal, got {other:?}"),
    }

    // Exactly at the limit is fine.
    let exact = "x".repeat(MAX_TITLE_LEN);
    let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{exact}\""));
    assert!(parse(&text).validate(&ManifestContext::default()).is_ok());
}

#[test]
fn a_long_title_is_measured_in_characters_not_bytes() {
    // A CJK title of the same character count is not "too long" in a unit the user cannot see.
    let cjk = "电".repeat(MAX_TITLE_LEN);
    let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{cjk}\""));
    assert!(parse(&text).validate(&ManifestContext::default()).is_ok());
}

#[test]
fn a_localised_title_is_chosen_by_tag_with_a_fallback_chain() {
    let text = MINIMAL.replace(
        "\"title\": \"Chat\"",
        "\"title\": \"Chat\", \"description\": \"Cross-device chat\", \"locales\": { \
             \"zh-CN\": { \"title\": \"聊天\", \"description\": \"跨设备聊天\" }, \
             \"zh\": { \"title\": \"中文\" }, \
             \"en\": { \"title\": \"Chat!\" } }",
    );
    let manifest = parse(&text);

    assert_eq!(
        manifest.localised_title("zh-CN"),
        "聊天",
        "an exact match wins"
    );
    assert_eq!(manifest.localised_title("en"), "Chat!");
    // The chain shortens the *reader's* tag: `zh-Hans-CN` looks for itself, then for `zh`. It does not
    // extend the manifest's, so a manifest declaring only `zh-CN` would not answer here.
    assert_eq!(manifest.localised_title("zh-Hans-CN"), "中文");
    // A language with no entry falls back to the default.
    assert_eq!(manifest.localised_title("fr"), "Chat");
    assert_eq!(
        manifest.localised_description("fr"),
        Some("Cross-device chat")
    );
    assert_eq!(manifest.localised_description("zh-CN"), Some("跨设备聊天"));
    // The `zh` entry has no description, so the reader gets the default rather than an empty string.
    assert_eq!(
        manifest.localised_description("zh-Hans-CN"),
        Some("Cross-device chat")
    );
}

#[test]
fn a_manifest_with_no_locales_uses_its_defaults() {
    let manifest = minimal();
    assert_eq!(manifest.localised_title("zh-CN"), "Chat");
    assert_eq!(manifest.localised_title(""), "Chat");
    assert_eq!(manifest.localised_description("zh-CN"), None);
}

#[test]
fn a_locale_missing_the_requested_string_falls_through() {
    // A `zh-CN` entry with only a `title` must not make the description disappear.
    let text = MINIMAL.replace(
        "\"title\": \"Chat\"",
        "\"title\": \"Chat\", \"description\": \"Cross-device chat\", \
             \"locales\": { \"zh-CN\": { \"title\": \"聊天\" } }",
    );
    let manifest = parse(&text);
    assert_eq!(manifest.localised_title("zh-CN"), "聊天");
    assert_eq!(
        manifest.localised_description("zh-CN"),
        Some("Cross-device chat")
    );
}
