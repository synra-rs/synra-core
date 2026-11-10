use super::super::{
    HostFacts, MAX_CLOCK_SKEW_SECS, MIN_WEBVIEW_MAJOR, ProbeStatus, clock_skew_within_tolerance,
    probe_clock_sanity, probe_wasm_backend, probe_webview_version,
};
use super::hosts;

#[test]
fn the_clock_is_plausible_in_a_test_process() {
    assert_eq!(probe_clock_sanity().status, ProbeStatus::Ok);
}

#[test]
fn a_recent_webview_passes_the_version_check() {
    let result = probe_webview_version(&HostFacts {
        webview_version: Some(format!("{MIN_WEBVIEW_MAJOR}.0.0")),
        ..hosts()
    });
    assert_eq!(result.status, ProbeStatus::Ok);
}

#[test]
fn an_old_webview_fails_with_advice() {
    let result = probe_webview_version(&HostFacts {
        webview_version: Some("90.0.4430.72".to_owned()),
        ..hosts()
    });
    assert_eq!(result.status, ProbeStatus::Fail);
    assert!(result.detail.contains("90.0.4430.72"));
    assert!(result.suggestion.is_some());
}

#[test]
fn a_webview_version_that_cannot_be_read_is_inconclusive() {
    // Not a failure: the interface may work perfectly, and claiming otherwise sends the user to update
    // something that is not the problem.
    for version in ["unknown", ""] {
        let result = probe_webview_version(&HostFacts {
            webview_version: Some(version.to_owned()),
            ..hosts()
        });
        assert_eq!(result.status, ProbeStatus::Warn, "{version:?}");
    }
}

#[test]
fn a_missing_webview_report_is_inconclusive_rather_than_a_failure() {
    let result = probe_webview_version(&HostFacts::default());
    assert_eq!(result.status, ProbeStatus::Warn);
    assert!(result.detail.contains("did not report"));
}


#[test]
fn wasm_backend_states_map_to_the_right_status() {
    assert_eq!(
        probe_wasm_backend(&HostFacts { wasm_backend_available: Some(true), ..Default::default() }).status,
        ProbeStatus::Ok
    );
    let broken = probe_wasm_backend(&HostFacts {
        wasm_backend_available: Some(false),
        ..Default::default()
    });
    assert_eq!(broken.status, ProbeStatus::Fail);
    assert!(broken.suggestion.is_some());
    assert_eq!(probe_wasm_backend(&HostFacts::default()).status, ProbeStatus::Warn);
}

#[test]
fn clock_skew_tolerance_is_symmetric_and_bounded() {
    assert!(clock_skew_within_tolerance(1_000, 1_000));
    assert!(clock_skew_within_tolerance(1_000, 1_000 + MAX_CLOCK_SKEW_SECS));
    assert!(clock_skew_within_tolerance(1_000 + MAX_CLOCK_SKEW_SECS, 1_000));
    assert!(!clock_skew_within_tolerance(1_000, 1_000 + MAX_CLOCK_SKEW_SECS + 1));
    assert!(!clock_skew_within_tolerance(1_000 + MAX_CLOCK_SKEW_SECS + 1, 1_000));
}

#[test]
fn clock_skew_does_not_underflow() {
    // A local clock at zero against a reference at the epoch must not wrap into a pass.
    assert!(clock_skew_within_tolerance(0, 0));
    assert!(!clock_skew_within_tolerance(0, u64::MAX));
}
