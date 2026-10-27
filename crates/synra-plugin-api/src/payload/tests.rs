use super::*;
use serde_json::json;

#[test]
fn required_fields_types_numeric_bounds_and_extra_fields_are_enforced() {
    let schema = PayloadSchema::compile(&json!({"type":"object","properties":{
        "text":{"type":"string","minLength":1,"maxLength":3},
        "count":{"type":"integer","minimum":1,"maximum":5},
        "kind":{"enum":["ready","stopped"]}},
        "required":["text","count","kind"],"additionalProperties":false}))
    .unwrap();
    assert!(
        schema
            .validate(&json!({"text":"中文🖱️","count":2,"kind":"ready"}))
            .is_err()
    );
    for valid in [
        json!({"text":"中文","count":2,"kind":"ready"}),
        json!({"text":"a","count":1.0,"kind":"stopped"}),
    ] {
        schema.validate(&valid).unwrap();
    }
    for invalid in [
        json!({}),
        json!({"text":"a","count":0,"kind":"ready"}),
        json!({"text":"a","count":2.1,"kind":"ready"}),
        json!({"text":"a","count":2,"kind":"other"}),
        json!({"text":"a","count":2,"kind":"ready","extra":true}),
    ] {
        assert!(
            matches!(schema.validate(&invalid), Err(PayloadError::Invalid { .. })),
            "{invalid}"
        );
    }
}

#[test]
fn nested_arrays_and_boolean_schemas_use_actual_schema_semantics() {
    let schema = PayloadSchema::compile(&json!({"type":"object","properties":{
        "items":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"number","minimum":0}},
        "blocked":false},"required":["items"]})).unwrap();
    schema.validate(&json!({"items":[1,2]})).unwrap();
    for invalid in [
        json!({"items":[]}),
        json!({"items":[1,1.0]}),
        json!({"items":[-1]}),
        json!({"items":[1],"blocked":null}),
    ] {
        assert!(schema.validate(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn property_names_and_literal_data_are_not_schema_keywords() {
    let schema = PayloadSchema::compile(&json!({"type":"object","properties":{
        "pattern":{"type":"string","maxLength":16},
        "format":{"const":{"$ref":"literal payload data"}}},"required":["pattern","format"]}))
    .unwrap();
    schema
        .validate(&json!({"pattern":"plain text","format":{"$ref":"literal payload data"}}))
        .unwrap();
    assert!(
        PayloadSchema::compile(
            &json!({"type":"object","properties":{"optional":{"type":["string","null"]}}})
        )
        .is_err()
    );
}

#[test]
fn references_patterns_formats_and_invalid_schemas_are_refused_locally() {
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef", "pattern", "format"] {
        let schema = json!({"type":"object","properties":{"secret":{(keyword):"https://127.0.0.1:9/unreachable"}}});
        assert!(PayloadSchema::compile(&schema).is_err(), "{keyword}");
    }
    for schema in [
        json!({"type":"object","properties":{"name":{"type":"string"}}}),
        json!({"type":"object","required":"x"}),
        json!({"type":"object","properties":{"name":{"type":"string","maxLength":-1}}}),
    ] {
        assert!(PayloadSchema::compile(&schema).is_err());
    }
}

#[test]
fn refusals_do_not_echo_payload_secrets_and_complexity_is_bounded() {
    let schema =
        PayloadSchema::compile(&json!({"type":"object","properties":{"secret":{"type":"number"}}}))
            .unwrap();
    let error = schema
        .validate(&json!({"secret":"private selection"}))
        .unwrap_err();
    assert_eq!(
        error,
        PayloadError::Invalid {
            path: "/secret".to_owned()
        }
    );
    assert!(!error.to_string().contains("private selection"));
    assert_eq!(
        schema.validate(&json!({"items":vec![0;257]})),
        Err(PayloadError::TooLarge)
    );
    let mut deep = json!({});
    for _ in 0..MAX_DEPTH + 1 {
        deep = json!({"nested":deep});
    }
    assert_eq!(schema.validate(&deep), Err(PayloadError::TooLarge));
}

#[test]
fn encoded_byte_budget_counts_all_fields_and_json_escaping_without_an_output_buffer() {
    let schema = PayloadSchema::compile(&json!({"type":"object"})).unwrap();
    schema
        .validate(&json!({"text":"\u{0000}".repeat(10_000)}))
        .unwrap();
    assert_eq!(
        schema.validate(&json!({"text":"\u{0000}".repeat(11_000)})),
        Err(PayloadError::TooLarge)
    );
    assert_eq!(
        schema.validate(&json!({"a":"x".repeat(40_000),"b":"x".repeat(40_000)})),
        Err(PayloadError::TooLarge)
    );
}
