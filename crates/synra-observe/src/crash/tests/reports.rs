use synra_protocol::TraceId;
use super::super::{CrashReport, RECENT_WINDOW, now_ms, panic_message};
use super::report;

#[test]
fn a_report_records_everything_a_hook_can_see() {
    let trace = TraceId::new();
    let report = CrashReport::new(
        1_700_000_000_000,
        "1.2.3",
        Some("src/kernel.rs:42:9".to_owned()),
        Some("boom".to_owned()),
        Some("sync".to_owned()),
        Some("0: backtrace".to_owned()),
        Some(trace),
    );

    assert_eq!(report.version, "1.2.3");
    assert_eq!(report.location_key(), Some("src/kernel.rs:42:9"));
    assert_eq!(report.trace_id, Some(trace));
    assert!(report.summary().contains("boom"));
    assert!(report.summary().contains("src/kernel.rs:42:9"));
}

#[test]
fn a_report_without_a_location_still_summarises() {
    let report = report(1_000, None);
    assert_eq!(report.location_key(), None);
    assert!(report.summary().contains("unknown location"));
}

#[test]
fn a_report_without_a_message_still_summarises() {
    let mut report = report(1_000, Some("a.rs:1:1"));
    report.message = None;
    assert!(report.summary().contains("no message"));
}

#[test]
fn recency_is_bounded_by_the_window() {
    let now = 1_700_000_000_000;
    let window_ms = i64::try_from(RECENT_WINDOW.as_millis()).expect("fits");

    assert!(report(now, Some("a")).is_recent(now));
    assert!(report(now - window_ms, Some("a")).is_recent(now), "exactly at the window");
    assert!(!report(now - window_ms - 1, Some("a")).is_recent(now), "one past it");
    // Yesterday's crash must not be offered as this morning's.
    assert!(!report(now - 86_400_000, Some("a")).is_recent(now));
}

#[test]
fn a_report_from_the_future_counts_as_recent() {
    // A clock that moved backwards — a suspend, a manual change — must not hide a crash. Treating a
    // future timestamp as old would do exactly that.
    let now = 1_000;
    assert!(report(now + 10_000_000, Some("a")).is_recent(now));
}

#[test]
fn a_report_round_trips_through_json() {
    // The report is written by the panic hook and read by the next start, so the shape has to survive
    // both, and the field names are camelCase like the rest of the project's data.
    let report = report(1_700_000_000_000, Some("a.rs:1:1"));
    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.contains("\"atMs\""), "{json}");
    assert!(!json.contains("at_ms"), "{json}");

    let back: CrashReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

#[test]
fn a_panic_message_is_read_from_both_shapes() {
    // `panic!("literal")` produces a `&str` and `panic!("{}", x)` produces a `String`; the hook offers
    // both through the same `Box<dyn Any>`.
    let literal: &'static str = "a literal panic";
    assert_eq!(panic_message(&literal), Some("a literal panic".to_owned()));

    let formatted = String::from("a formatted panic");
    assert_eq!(panic_message(&formatted), Some("a formatted panic".to_owned()));

    // Something else entirely yields nothing rather than a pointer rendering.
    let number: u32 = 42;
    assert_eq!(panic_message(&number), None);
}

#[test]
fn the_clock_helper_returns_a_plausible_timestamp() {
    // After 2020 and before 2100, so a broken clock is caught rather than silently written into reports.
    let now = now_ms();
    assert!(now > 1_577_836_800_000, "{now}");
    assert!(now < 4_102_444_800_000, "{now}");
}
