//! The logging module's tests.

use super::*;
use crate::redact::Redaction;
use rstest::rstest;
use std::sync::atomic::AtomicI64;

use std::sync::Arc;
use crate::redact::REDACTED;

use std::sync::atomic::Ordering;
use crate::redact::Redactor;
use std::io::Write as _;

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
fn the_writer_applies_the_policy_and_counts_it() {
    let mut writer = RedactingWriter::new(Vec::new());
    let stats = writer.stats();

    let secret = "the secret message";
    let line = format!("payload={secret} peer=abc\n");
    writer.write_all(line.as_bytes()).expect("writes");
    writer.flush().expect("flushes");

    assert_eq!(stats.lines(), 1);
    assert_eq!(stats.redactions(), 1);
    assert!(stats.bytes() > 0);

    let output = String::from_utf8(writer.inner.lock().clone()).expect("utf8");
    assert!(!output.contains(secret), "{output}");
    assert!(output.contains("peer=abc"), "{output}");
}

#[test]
fn the_writer_can_be_turned_off_for_a_test_that_needs_raw_text() {
    let mut writer = RedactingWriter::new(Vec::new());
    writer.set_enabled(false);
    writer.write_all(b"token=abc\n").expect("writes");

    let output = String::from_utf8(writer.inner.lock().clone()).expect("utf8");
    assert!(output.contains("token=abc"), "{output}");
    // And a disabled writer must not claim to have withheld anything.
    assert_eq!(writer.stats().redactions(), 0);
}

#[test]
fn the_writer_passes_non_utf8_through_rather_than_failing() {
    // A dropped log line is worse than a garbled one, and an error here would propagate into whatever
    // was being logged.
    let mut writer = RedactingWriter::new(Vec::new());
    let bytes = [0xFFu8, 0xFE, b'\n'];
    writer.write_all(&bytes).expect("writes");
    writer.flush().expect("flushes");

    let output = writer.inner.lock().clone();
    assert_eq!(output, bytes);
}

#[test]
fn the_writer_reports_how_much_it_wrote() {
    // The `Write` contract: a short count makes the caller retry or, worse, silently drop the rest.
    let mut writer = RedactingWriter::new(Vec::new());
    let line = b"peer=abc\n";
    assert_eq!(writer.write(line).expect("writes"), line.len());
}

#[test]
fn a_writer_displays_without_exposing_its_target() {
    let writer = RedactingWriter::new(Vec::new());
    let debug = format!("{writer:?}");
    assert!(debug.contains("RedactingWriter"), "{debug}");
}

#[test]
fn levels_order_from_most_to_least_verbose() {
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Error);
}

#[test]
fn a_threshold_admits_its_own_level_and_worse() {
    assert!(LogLevel::Info.admits(LogLevel::Info));
    assert!(LogLevel::Info.admits(LogLevel::Warn));
    assert!(LogLevel::Info.admits(LogLevel::Error));
    assert!(!LogLevel::Info.admits(LogLevel::Debug));
    assert!(!LogLevel::Info.admits(LogLevel::Trace));

    // Off admits nothing, including an error.
    for level in [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ] {
        assert!(!LogLevel::Off.admits(level), "{level}");
    }
}

#[test]
fn only_the_persisted_levels_reach_disk() {
    // Debug and trace are for a bounded diagnostic window; keeping them forever is how a log
    // directory reaches a gigabyte.
    assert!(!LogLevel::Trace.is_persisted());
    assert!(!LogLevel::Debug.is_persisted());
    assert!(LogLevel::Info.is_persisted());
    assert!(LogLevel::Warn.is_persisted());
    assert!(LogLevel::Error.is_persisted());
}

#[test]
fn level_names_round_trip() {
    for level in [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
        LogLevel::Off,
    ] {
        assert_eq!(LogLevel::parse(level.as_str()), Ok(level));
        assert_eq!(level.to_string(), level.as_str());
    }
    // Case and whitespace are tolerated, because these come from a config file a person edited.
    assert_eq!(LogLevel::parse("  INFO "), Ok(LogLevel::Info));
    assert_eq!(LogLevel::parse("WARNING"), Ok(LogLevel::Warn));
    assert!(LogLevel::parse("loud").is_err());
}

#[test]
fn the_default_level_is_info() {
    assert_eq!(LogLevel::default(), LogLevel::Info);
}

#[test]
fn an_unknown_level_names_itself_in_the_error() {
    match LogLevel::parse("loud") {
        Err(error) => assert_eq!(error.name, "loud"),
        Ok(level) => panic!("expected an error, got {level}"),
    }
}

#[test]
fn a_temporary_increase_expires_on_its_own() {
    // The clock is injected, so this asserts the deadline rather than sleeping for thirty minutes.
    let base = std::time::Instant::now();
    let offset = Arc::new(AtomicI64::new(0));
    let offset_for_clock = Arc::clone(&offset);

    let verbosity = Verbosity::with_clock(LogLevel::Info, move || {
        let seconds = offset_for_clock.load(Ordering::Relaxed);
        if seconds >= 0 {
            base + core::time::Duration::from_secs(seconds as u64)
        }
        else {
            base - core::time::Duration::from_secs(seconds.unsigned_abs())
        }
    });

    assert_eq!(verbosity.effective(), LogLevel::Info);
    assert!(!verbosity.is_raised());

    verbosity.raise_for_a_while(LogLevel::Debug);
    assert_eq!(verbosity.effective(), LogLevel::Debug);
    assert!(verbosity.is_raised());
    assert_eq!(verbosity.remaining(), Some(VERBOSE_WINDOW));

    // Just inside the window.
    offset.store(i64::try_from(VERBOSE_WINDOW.as_secs()).expect("small") - 1, Ordering::Relaxed);
    assert_eq!(verbosity.effective(), LogLevel::Debug);

    // Past it.
    offset.store(i64::try_from(VERBOSE_WINDOW.as_secs()).expect("small") + 1, Ordering::Relaxed);
    assert_eq!(verbosity.effective(), LogLevel::Info, "the override must lapse");
    assert!(!verbosity.is_raised());
    assert_eq!(verbosity.remaining(), None);
}

#[test]
fn a_temporary_increase_can_be_ended_immediately() {
    let verbosity = Verbosity::new(LogLevel::Info);
    verbosity.raise_for_a_while(LogLevel::Trace);
    assert_eq!(verbosity.effective(), LogLevel::Trace);

    verbosity.reset();
    assert_eq!(verbosity.effective(), LogLevel::Info);
}

#[test]
fn a_temporary_increase_can_be_given_an_explicit_deadline() {
    // The settings screen shows a countdown, so it already knows the deadline.
    let verbosity = Verbosity::new(LogLevel::Warn);
    let until = std::time::Instant::now() + core::time::Duration::from_secs(60);
    verbosity.raise_until(LogLevel::Debug, until);

    assert_eq!(verbosity.effective(), LogLevel::Debug);
    assert_eq!(verbosity.configured(), LogLevel::Warn);
    // The remaining time is asserted as a range rather than a value: reading the clock between the
    // caller's `Instant::now()` and this assertion makes an exact comparison flaky by nanoseconds.
    let remaining = verbosity.remaining().expect("a deadline is set");
    assert!(
        remaining <= core::time::Duration::from_secs(60)
            && remaining > core::time::Duration::from_secs(59),
        "{remaining:?}",
    );
}

#[test]
fn raising_again_replaces_the_previous_deadline() {
    let verbosity = Verbosity::new(LogLevel::Info);
    verbosity.raise_for_a_while(LogLevel::Debug);
    verbosity.raise_for_a_while(LogLevel::Trace);
    assert_eq!(verbosity.effective(), LogLevel::Trace, "the latest request wins");
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
fn the_writer_reports_a_shorter_redaction_than_it_consumed() {
    // The `Write` contract wants the count of bytes *consumed*, not written: returning the shorter
    // figure makes the caller re-send the tail of the redacted value.
    let mut writer = RedactingWriter::new(Vec::new());
    let line = b"token=a\n";
    assert_eq!(writer.write(line).expect("writes"), line.len());
}

#[test]
fn redaction_is_reported_through_the_stats() {
    let mut writer = RedactingWriter::new(Vec::new());
    let stats = writer.stats();
    writer.write_all(b"token=a token=b\n").expect("writes");

    assert_eq!(stats.redactions(), 2, "both fields");
    // And a second writer has its own counters.
    let other = RedactingWriter::new(Vec::new());
    assert_eq!(other.stats().redactions(), 0);
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
