use super::super::{REDACTED, Redaction, Redactor};

#[test]
fn a_long_value_is_truncated_with_its_original_length() {
    let redactor = Redactor::with_max_value_len(16);
    let long = "x".repeat(100);
    let redacted = redactor.value("peer", &long);

    assert_eq!(redacted.decision, Redaction::Truncated { original_len: 100 });
    // Sixteen kept characters, then the marker and the length.
    assert!(redacted.text.starts_with(&"x".repeat(16)), "{}", redacted.text);
    assert!(redacted.text.contains("len=100"), "{}", redacted.text);
    // And the value is no longer present in full.
    assert!(!redacted.text.contains(&long));
}

#[test]
fn a_value_exactly_at_the_cap_is_untouched() {
    // The boundary is inclusive, so a cap of 16 keeps a 16-character value intact.
    let redactor = Redactor::with_max_value_len(16);
    let exact = "y".repeat(16);
    assert_eq!(redactor.value("peer", &exact).decision, Redaction::Untouched);

    let one_more = "y".repeat(17);
    assert!(redactor.value("peer", &one_more).decision.withheld_something());
}

#[test]
fn truncation_counts_characters_not_bytes() {
    // A length measured in bytes would cut a multi-byte character in half and produce invalid UTF-8,
    // which `String` cannot even hold — so the failure would be a panic rather than a bad log line.
    let redactor = Redactor::with_max_value_len(4);
    let cjk = "电".repeat(10);
    let redacted = redactor.value("peer", &cjk);
    assert!(redacted.text.starts_with("电电电电"), "{}", redacted.text);
    assert!(redacted.text.contains("len=10"), "{}", redacted.text);
}

#[test]
fn a_non_string_value_is_redacted_by_its_debug_form() {
    // `payload = ?value` where the value is a parsed JSON tree is the most common way to leak a
    // message body, and it renders as a string.
    let redactor = Redactor::new();
    let value = serde_json::json!({ "body": "the secret message" });
    let redacted = redactor.debug_value("payload", &value);
    assert_eq!(redacted.text, REDACTED);
    assert!(!redacted.text.contains("secret"));
}

#[test]
fn an_ordinary_non_string_value_is_readable() {
    let redactor = Redactor::new();
    assert_eq!(redactor.debug_value("peer_count", &3u32).text, "3");
    assert_eq!(redactor.display_value("elapsed_ms", &12u64).text, "12");
    assert_eq!(
        redactor.display_value("elapsed_ms", &12u64).decision,
        Redaction::Untouched
    );
}

#[test]
fn a_redacted_value_displays_as_its_text() {
    let redactor = Redactor::new();
    assert_eq!(redactor.value("token", "abc").to_string(), REDACTED);
    assert_eq!(redactor.value("peer", "abc").to_string(), "abc");
}

#[test]
fn a_zero_cap_still_produces_readable_output() {
    // A degenerate configuration must not produce a log line that a reader cannot interpret.
    let redactor = Redactor::with_max_value_len(0);
    let redacted = redactor.value("peer", "abc");
    assert_eq!(redacted.decision, Redaction::Truncated { original_len: 3 });
    assert!(redacted.text.contains("len=3"), "{}", redacted.text);
}
