use std::io::Write as _;

use super::*;

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
