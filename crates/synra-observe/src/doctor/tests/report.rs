use super::super::{ProbeReport, ProbeResult, ProbeStatus};

#[test]
fn a_passing_probe_has_nothing_to_suggest() {
    let result = ProbeResult::ok("check", "all good");
    assert_eq!(result.status, ProbeStatus::Ok);
    assert_eq!(result.suggestion, None);
    assert!(!result.status.needs_attention());
}

#[test]
fn a_warning_and_a_failure_both_suggest_something() {
    // A probe that reports a problem without a suggestion has moved the work onto the user without giving
    // them the means to do it.
    for result in [
        ProbeResult::warn("check", "nearly full", "free some space"),
        ProbeResult::fail("check", "no space", "free some space"),
        ProbeResult::unknown("check", "could not tell"),
    ] {
        assert!(result.suggestion.is_some(), "{result:?}");
        assert!(result.status.needs_attention());
    }
}

#[test]
fn an_inconclusive_probe_is_a_warning_not_a_failure() {
    // `Fail` claims the feature is broken. Not being able to tell is a different claim, and a diagnostic
    // that cries wolf is one people learn to ignore.
    let result = ProbeResult::unknown("check", "could not tell");
    assert_eq!(result.status, ProbeStatus::Warn);
}

#[test]
fn statuses_order_from_ok_to_fail() {
    // The ordering is what `worst` relies on.
    assert!(ProbeStatus::Ok < ProbeStatus::Warn);
    assert!(ProbeStatus::Warn < ProbeStatus::Fail);
}

#[test]
fn a_report_reports_the_worst_status_it_holds() {
    // One failure among ten passes is a failing report, not a passing one.
    let mut report = ProbeReport::new();
    report.push(ProbeResult::ok("a", "fine"));
    report.push(ProbeResult::warn("b", "nearly", "do something"));
    report.push(ProbeResult::fail("c", "broken", "fix it"));
    report.push(ProbeResult::ok("d", "fine"));

    assert_eq!(report.worst(), ProbeStatus::Fail);
    assert!(report.needs_attention());
    assert_eq!(report.counts(), (2, 1, 1));
    assert!(report.summarise().contains("1 problem"));
    assert_eq!(report.problems().len(), 2);
}

#[test]
fn a_report_of_passes_says_so() {
    let mut report = ProbeReport::new();
    report.push(ProbeResult::ok("a", "fine"));
    report.push(ProbeResult::ok("b", "fine"));

    assert_eq!(report.worst(), ProbeStatus::Ok);
    assert!(!report.needs_attention());
    assert_eq!(report.summarise(), "all 2 checks passed");
    assert!(report.problems().is_empty());
}

#[test]
fn an_empty_report_is_not_a_problem() {
    let report = ProbeReport::new();
    assert_eq!(report.worst(), ProbeStatus::Ok);
    assert!(!report.needs_attention());
    assert!(report.results.is_empty());
}

#[test]
fn a_report_summarises_warnings_without_failures() {
    let mut report = ProbeReport::new();
    report.push(ProbeResult::ok("a", "fine"));
    report.push(ProbeResult::warn("b", "nearly", "do something"));

    assert_eq!(report.worst(), ProbeStatus::Warn);
    assert!(report.summarise().contains("1 warning"));
    assert!(!report.summarise().contains("problem"));
}

#[test]
fn a_result_can_be_found_by_name() {
    // The name is what a support conversation quotes, so it has to be a lookup key.
    let mut report = ProbeReport::new();
    report.push(ProbeResult::ok("clock_sanity", "plausible"));
    assert!(report.get("clock_sanity").is_some());
    assert!(report.get("nothing").is_none());
}

#[test]
fn a_status_round_trips_through_json() {
    for status in [ProbeStatus::Ok, ProbeStatus::Warn, ProbeStatus::Fail] {
        let json = serde_json::to_string(&status).expect("serialises");
        assert_eq!(json, format!("\"{}\"", status.as_str()));
        let back: ProbeStatus = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, status);
    }
}

#[test]
fn a_probe_result_round_trips_with_camel_case_fields() {
    let result = ProbeResult::fail("clock_sanity", "wrong", "set the clock");
    let json = serde_json::to_string(&result).expect("serialises");
    assert!(json.contains("\"name\""), "{json}");
    assert!(json.contains("\"suggestion\""), "{json}");
    // A passing probe omits its suggestion rather than writing null, so a reader never handles both.
    let passing = serde_json::to_string(&ProbeResult::ok("x", "fine")).expect("serialises");
    assert!(passing.contains("\"suggestion\":null") || !passing.contains("suggestion"), "{passing}");

    let back: ProbeResult = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, result);
}

#[test]
fn a_report_serialises_as_a_bare_list() {
    // The bundle carries it, and a transparent list is what an interface expects to iterate.
    let mut report = ProbeReport::new();
    report.push(ProbeResult::ok("a", "fine"));

    let json = serde_json::to_string(&report).expect("serialises");
    assert!(json.starts_with('['), "{json}");

    let back: ProbeReport = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, report);
}

#[test]
fn a_probe_result_displays_its_status() {
    assert_eq!(ProbeStatus::Ok.to_string(), "ok");
    assert_eq!(ProbeStatus::Warn.to_string(), "warn");
    assert_eq!(ProbeStatus::Fail.to_string(), "fail");
}

#[test]
fn a_result_reports_its_name_as_its_title() {
    assert_eq!(ProbeResult::ok("clock_sanity", "fine").title(), "clock_sanity");
}
