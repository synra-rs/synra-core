use super::*;

/// The test the design document asks for by name: pass a payload to the log path and assert the
/// original text is absent from the output.
#[test]
fn a_payload_never_reaches_the_output() {
    let secret = "the secret message";

    // As a formatted `tracing` line, which is what the writer sees.
    let line = format!("event=transport.recv payload={secret} peer=abc\n");
    let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

    assert!(!redacted.contains(secret), "{redacted}");
    assert!(redacted.contains(REDACTED), "{redacted}");
    assert_eq!(count, 1);
    // And the rest of the line survives, because the diagnosis is the point of logging at all.
    assert!(redacted.contains("peer=abc"), "{redacted}");
}

#[rstest]
#[case("payload", r#"{"body":"x"}"#)]
#[case("body", "the secret message")]
#[case("content", "file contents")]
#[case("clipboard", "copied text")]
#[case("token", "ghp_abc123")]
#[case("access_token", "ya29.abc")]
#[case("api_key", "sk-live-abc")]
#[case("secret", "hunter2")]
#[case("password", "hunter2")]
#[case("credential", "user:pass")]
#[case("cookie", "session=abc")]
#[case("private_key", "-----BEGIN")]
#[case("session_key", "0123456789")]
fn a_secret_field_is_redacted_in_a_formatted_line(#[case] field: &str, #[case] value: &str) {
    let line = format!("ts=1 level=INFO {field}={value} done=true\n");
    let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

    assert!(!redacted.contains(value), "{field}: {redacted}");
    assert!(redacted.contains(REDACTED), "{field}: {redacted}");
    assert_eq!(count, 1, "{field}");
}

#[test]
fn a_url_query_is_stripped_from_a_formatted_line() {
    let line = "event=http.request url=https://api.github.com/repos?token=ghp_abc status=200\n";
    let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);

    assert!(!redacted.contains("ghp_abc"), "{redacted}");
    assert!(redacted.contains("https://api.github.com/repos"), "{redacted}");
    assert!(redacted.contains("status=200"), "{redacted}");
    assert_eq!(count, 1);
}

#[test]
fn ordinary_fields_are_left_exactly_as_written() {
    let line = "event=transport.send peer=abc elapsed_ms=12 ok=true\n";
    let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
    assert_eq!(redacted, line, "an untouched line must not be reflowed");
    assert_eq!(count, 0);
}

#[test]
fn several_secrets_on_one_line_are_all_replaced() {
    let line = "payload=abc token=def peer=ok secret=ghi\n";
    let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);

    assert_eq!(count, 3);
    for leaked in ["abc", "def", "ghi"] {
        assert!(!redacted.contains(leaked), "{leaked} survived: {redacted}");
    }
    assert!(redacted.contains("peer=ok"), "{redacted}");
}

#[test]
fn a_line_with_no_equals_sign_survives_intact() {
    // A panic message, a stack frame, a blank line: none of them have the shape this looks for, and
    // mangling them would lose the diagnostic.
    for line in ["thread 'main' panicked at src/lib.rs:1", "", "---- ---- ----", "  at foo"] {
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
        assert_eq!(redacted, line, "{line:?}");
        assert_eq!(count, 0, "{line:?}");
    }
}

#[test]
fn a_field_at_the_start_of_a_line_is_found() {
    // The name search runs back to a space, and there is none at the start of the line.
    let (redacted, count) = redact_line("token=abc rest=1", DEFAULT_REDACTED_FIELDS, true);
    assert!(redacted.starts_with(&format!("token={REDACTED}")), "{redacted}");
    assert_eq!(count, 1);
}

#[test]
fn url_stripping_can_be_disabled_independently_of_field_redaction() {
    let line = "url=https://x/y?t=1 token=abc\n";
    let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, false);
    // The secret is still gone; only the URL treatment changed.
    assert!(!redacted.contains("abc"), "{redacted}");
    assert!(redacted.contains("https://x/y?t=1"), "{redacted}");
    assert_eq!(count, 1);
}

#[test]
fn a_caller_can_supply_its_own_field_list() {
    let line = "session=abc peer=ok\n";
    let (redacted, count) = redact_line(line, &["session"], true);
    assert!(redacted.contains(REDACTED), "{redacted}");
    assert_eq!(count, 1);

    let (untouched, count) = redact_line(line, &["nothing"], true);
    assert!(untouched.contains("session=abc"), "{untouched}");
    assert_eq!(count, 0);
}

#[test]
fn a_truncated_url_is_counted_and_a_truncated_value_is_not() {
    // Truncation is not withholding a secret, so counting it would make the redaction number
    // misleading — it would report that secrets were caught when none were.
    let long = format!("{}?q=1", "https://example.com/".repeat(60));
    let line = format!("url={long} note=ok\n");
    let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

    // The URL's query was removed, which *is* a redaction.
    assert_eq!(count, 1, "{redacted}");
    assert!(redacted.contains("len="), "the value was also truncated: {redacted}");
    assert!(redacted.contains("note=ok"), "{redacted}");

    // A long value that is not a URL is truncated without being counted. The value is a repeated
    // word rather than a repeated letter, so "the original is absent" is a real assertion: a single
    // repeated character also occurs inside `level=INFO`.
    let plain = "abcdefghij".repeat(200);
    let (redacted, count) = redact_line(&format!("note={plain}\n"), DEFAULT_REDACTED_FIELDS, true);
    assert_eq!(count, 0, "{redacted}");
    assert!(redacted.contains("len=2001"), "{redacted}");
    assert!(!redacted.contains(&plain), "the value was not truncated");
}

#[test]
fn a_field_name_is_matched_case_insensitively_in_a_formatted_line() {
    let line = "TOKEN=abc Peer=ok\n";
    let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
    assert!(!redacted.contains("abc"), "{redacted}");
    assert_eq!(count, 1);
}

#[test]
fn a_url_decision_is_not_reported_as_truncation() {
    // The distinction matters to a consumer that renders the reason: "query removed" and "too long"
    // send a reader looking in different places.
    let redactor = Redactor::new();
    assert!(matches!(
        redactor.value("url", "https://x/y?a=1").decision,
        Redaction::UrlStripped { .. }
    ));
}
