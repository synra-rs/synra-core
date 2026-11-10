use crate::ids::DeviceId;

use super::super::{Feature, Hello, HelloError, SessionNonce};
use super::hello;

#[test]
fn a_valid_hello_passes_validation() {
    assert_eq!(hello().validate(), Ok(()));
}

#[test]
fn a_hello_from_another_protocol_version_is_refused() {
    let mut hello = hello();
    hello.protocol = 2;
    assert!(matches!(hello.validate(), Err(HelloError::Version(_))));
}

#[test]
fn a_hello_missing_essentials_is_refused() {
    /// Mutates one field of a hello, so a table of negative cases can be one loop.
    type Mutate = fn(&mut Hello);
    let cases: &[(&str, Mutate)] = &[
        ("nil device", |h| h.device_id = DeviceId::from_uuid(uuid::Uuid::nil())),
        ("zero nonce", |h| h.nonce = SessionNonce(0)),
        ("blank name", |h| h.display_name = "  ".to_owned()),
        ("long name", |h| h.display_name = "x".repeat(Hello::MAX_DISPLAY_NAME + 1)),
        ("blank version", |h| h.app_version = String::new()),
    ];

    for (label, mutate) in cases {
        let mut hello = hello();
        mutate(&mut hello);
        assert!(hello.validate().is_err(), "{label} should be refused");
    }
}

#[test]
fn too_many_endpoints_is_refused() {
    // The list drives connection attempts on the receiver, so it is bounded input.
    let mut hello = hello();
    hello.endpoints = (0..=Hello::MAX_ENDPOINTS)
        .map(|i| format!("10.0.0.{i}:32100"))
        .collect();
    assert!(hello.validate().is_err());

    hello.endpoints.truncate(Hello::MAX_ENDPOINTS);
    assert_eq!(hello.validate(), Ok(()));
}

#[test]
fn a_required_feature_must_also_be_offered() {
    // Otherwise the announcement contradicts itself, and negotiation would report a feature as
    // missing that the peer never claimed to have.
    let mut hello = hello();
    hello.features = vec![Feature::EventStream];
    hello.requires = vec![Feature::TransferResume];
    assert!(hello.validate().is_err());

    hello.requires = vec![Feature::EventStream];
    assert_eq!(hello.validate(), Ok(()));
}

#[test]
fn a_hello_round_trips_through_json() {
    let mut hello = hello();
    hello.features = vec![Feature::EventStream, Feature::TransferResume];
    hello.requires = vec![Feature::EventStream];
    hello.endpoints = vec!["192.168.1.5:32100".to_owned(), "[::1]:32100".to_owned()];

    let json = serde_json::to_string(&hello).expect("serialises");
    assert!(json.contains("\"deviceId\""), "{json}");
    let back: Hello = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, hello);
}

#[test]
fn optional_hello_fields_are_omitted_not_null() {
    let json = serde_json::to_string(&hello()).expect("serialises");
    for absent in ["\"requires\"", "\"endpoints\""] {
        assert!(!json.contains(absent), "{absent} should be omitted: {json}");
    }
}

#[test]
fn an_unknown_hello_field_is_refused() {
    let mut value = serde_json::to_value(hello()).expect("value");
    value
        .as_object_mut()
        .expect("an object")
        .insert("extra".to_owned(), serde_json::json!(1));
    assert!(serde_json::from_value::<Hello>(value).is_err());
}
