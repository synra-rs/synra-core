use rstest::rstest;
use super::super::error::ManifestError;
use super::super::types::{Manifest, ManifestContext};
use super::{MINIMAL, parse};

#[test]
fn a_payload_schema_must_be_a_top_level_object() {
    for payload in [
        r#"{ "type": "array" }"#,
        r#"{ "type": "string", "maxLength": 10 }"#,
        r#"{ "properties": {} }"#,
        r#"[1, 2]"#,
    ] {
        let text = MINIMAL.replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                &format!(
                    "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                     \"events\": [{{ \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": {payload} }}]"
                ),
            );
        let manifest = parse(&text);
        assert!(
            matches!(
                manifest.validate(&ManifestContext::default()),
                Err(ManifestError::BadPayloadSchema { .. })
            ),
            "{payload} should be refused for its shape"
        );
    }
}

#[rstest]
#[case(
    r##"{ "type": "object", "properties": { "a": { "$ref": "#/x" } } }"##,
    "$ref"
)]
#[case(r#"{ "type": "object", "properties": { "a": { "type": "string", "format": "email", "maxLength": 5 } } }"#, "format")]
#[case(r#"{ "type": "object", "properties": { "a": { "type": "string", "pattern": "^x$", "maxLength": 5 } } }"#, "pattern")]
#[case(
    r#"{ "type": "object", "patternProperties": {} }"#,
    "patternProperties"
)]
fn a_schema_using_something_the_host_cannot_enforce_is_refused(
    #[case] payload: &str,
    #[case] needle: &str,
) {
    // Each is a validator the host does not have, so honouring the rest while ignoring it would be a
    // partial check reported as a complete one.
    let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": {payload} }}]"
            ),
        );
    let manifest = parse(&text);
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::BadPayloadSchema { detail, .. }) => {
            assert!(
                detail.contains(needle),
                "{detail} does not mention {needle}"
            );
        }
        other => panic!("expected a schema refusal, got {other:?}"),
    }
}

#[test]
fn a_string_property_must_be_bounded() {
    // A string with no `maxLength` is one whose length the host cannot bound, so the payload validator
    // cannot promise anything about it — and the promise is what the receiving side trusted.
    let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.text\", \
             \"payload\": { \"type\": \"object\", \"properties\": { \"body\": { \"type\": \"string\" } } } }]",
        );
    let manifest = parse(&text);
    match manifest.validate(&ManifestContext::default()) {
        Err(ManifestError::BadPayloadSchema { detail, .. }) => {
            assert!(detail.contains("maxLength"), "{detail}");
        }
        other => panic!("expected a bounds refusal, got {other:?}"),
    }

    // With the bound, it passes.
    let bounded = text.replace(
        "\"type\": \"string\"",
        "\"type\": \"string\", \"maxLength\": 65536",
    );
    assert_eq!(
        parse(&bounded).validate(&ManifestContext::default()),
        Ok(())
    );
}

#[test]
fn a_non_numeric_bound_is_refused() {
    let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.text\", \
             \"payload\": { \"type\": \"object\", \"properties\": { \"body\": \
             { \"type\": \"string\", \"maxLength\": \"lots\" } } } }]",
        );
    assert!(parse(&text).validate(&ManifestContext::default()).is_err());
}

#[test]
fn a_deeply_nested_payload_schema_is_refused() {
    // Either a mistake or an attempt to make the loader's walk expensive.
    let mut nested = String::from(r#"{ "type": "object", "properties": { "a": "#);
    for _ in 0..20 {
        nested = format!("{nested} {{ \"type\": \"object\", \"properties\": {{ \"a\": ");
    }
    nested.push_str("{}");
    for _ in 0..21 {
        nested.push_str(" } }");
    }
    nested.push_str(" }");

    let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": {nested} }}]"
            ),
        );
    // Parsing may fail first if the fixture is malformed; either way it is refused rather than walked.
    if let Ok(manifest) = Manifest::from_json(&text) {
        assert!(
            manifest.validate(&ManifestContext::default()).is_err(),
            "a deeply nested schema should be refused"
        );
    }
}
