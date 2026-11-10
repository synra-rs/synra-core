use super::super::{REDACTED, Redaction, Redactor};

/// The secrets the design document lists as never loggable.
const FORBIDDEN: &[(&str, &str)] = &[
    ("payload", r#"{"body":"the secret message"}"#),
    ("body", "the secret message"),
    ("content", "file contents here"),
    ("clipboard", "copied password"),
    ("text", "a chat message"),
    ("token", "ghp_0123456789abcdef"),
    ("access_token", "ya29.abcdef"),
    ("api_key", "sk-live-abcdef"),
    ("apikey", "sk-live-abcdef"),
    ("secret", "hunter2"),
    ("password", "hunter2"),
    ("credential", "user:pass"),
    ("authToken", "Bearer abc"),
    ("Authorization", "Bearer abc"),
    ("cookie", "session=abc"),
    ("private_key", "-----BEGIN PRIVATE KEY-----"),
    ("session_key", "0123456789abcdef"),
    ("secure_value", "a stored secret"),
    ("keyring_value", "a stored secret"),
    ("userSecret", "shh"),
    ("request_body", "POST /x HTTP/1.1"),
    ("file_data", "binary"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.e30.x"),
];

#[test]
fn every_forbidden_field_is_replaced_whatever_it_holds() {
    // The property the module exists for, asserted per field so a removed fragment names the field
    // that stopped being protected.
    let redactor = Redactor::new();
    for (field, value) in FORBIDDEN {
        let redacted = redactor.value(field, value);
        assert_eq!(
            redacted.decision,
            Redaction::Replaced,
            "field {field:?} was not redacted",
        );
        assert!(!redacted.text.contains(value), "{field:?} leaked its value");
        assert_eq!(redacted.text, REDACTED);
    }
}

#[test]
fn a_secret_field_is_replaced_even_when_the_value_is_empty() {
    // An empty value is not an excuse to skip the decision: a field that is sometimes empty and
    // sometimes a token is exactly the one a policy that short-circuits on emptiness gets wrong.
    let redactor = Redactor::new();
    let redacted = redactor.value("token", "");
    assert_eq!(redacted.decision, Redaction::Replaced);
    assert_eq!(redacted.text, REDACTED);
}

#[test]
fn field_names_are_matched_case_insensitively_and_as_substrings() {
    for field in [
        "TOKEN",
        "Token",
        "authToken",
        "user_access_token",
        "my_secret_thing",
        "PAYLOAD",
        "requestBody",
        "x-clipboard-text",
    ] {
        assert!(Redactor::is_secret_field(field), "{field} should be treated as secret");
    }
}

#[test]
fn ordinary_field_names_are_not_redacted() {
    for field in ["peer", "device_id", "elapsed_ms", "event", "trace_id", "port", "count"] {
        assert!(!Redactor::is_secret_field(field), "{field} should be loggable");
    }
}

#[test]
fn over_redaction_is_the_deliberate_direction() {
    // `body_count` is harmless and is redacted anyway. Stated as a test so the trade-off is visible:
    // a slightly less useful log is preferable to a leaked secret, and a whole-name match would miss
    // `bodyLen` and its relatives.
    assert!(Redactor::is_secret_field("body_count"));
    assert_eq!(Redactor::new().value("body_count", "3").text, REDACTED);
}
