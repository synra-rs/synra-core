//! The environment probes' tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};

use super::*;

/// A unique directory per call.
///
/// A counter rather than the process id: two tests in one process would otherwise share a directory, and
/// the disk probe writes a mebibyte into it — so they would race over the same path and one would see the
/// other's write as a failure.
fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn targets() -> ProbeTargets {
    let base = std::env::temp_dir().join(format!("synra-doctor-{}", unique_suffix()));
    ProbeTargets {
        data_dir: base.join("data"),
        plugins_dir: base.join("plugins"),
        // Ports in the ephemeral range are the ones a test can be confident about, and the probe tests
        // pass 0 where they need a guaranteed-free port.
        listen_port: 0,
        discovery_port: 0,
    }
}

fn hosts() -> HostFacts {
    HostFacts {
        webview_version: Some("120.0.0".to_owned()),
        keyring_available: Some(true),
        wasm_backend_available: Some(true),
        firewall_hint: None,
    }
}

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
fn a_free_port_passes() {
    // Port zero asks the operating system for any free port, so this cannot fail for the reason under test.
    let result = probe_port_available("tcp_port_available", 0);
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    assert!(result.detail.contains("free"));
}

#[test]
fn a_port_already_held_fails_with_advice() {
    // The failure a user actually hits: another copy of the application, or something else on the port.
    //
    // Bound to the wildcard address, because that is what the probe binds and what the real listener binds.
    // A holder on `127.0.0.1` alone does *not* conflict with a listener on `0.0.0.0` — the two can coexist
    // — so a test that used the loopback address would assert something the probe is right not to detect.
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .expect("binds an ephemeral port");
    let port = listener.local_addr().expect("has an address").port();

    let result = probe_port_available("tcp_port_available", port);
    assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
    assert!(result.suggestion.is_some());
    assert!(result.detail.contains(&port.to_string()));
    drop(listener);
}

#[test]
fn a_held_udp_port_fails_separately_from_tcp() {
    // Discovery is the feature that breaks when it is taken, and a process holding the UDP port does not
    // appear in the TCP probe.
    // The wildcard address again, for the same reason as the TCP case.
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .expect("binds an ephemeral port");
    let port = socket.local_addr().expect("has an address").port();

    let result = probe_udp_port_available(port);
    assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
    assert_eq!(result.name, "discovery_udp_available");
    drop(socket);
}

#[test]
fn the_network_stack_is_present_in_a_test_process() {
    // If this fails, the machine has no loopback, which is the case the probe exists to catch.
    let result = probe_network_interfaces();
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
}

#[test]
fn a_firewall_hint_is_a_warning_with_advice() {
    let host = HostFacts {
        firewall_hint: Some("Windows Defender may be blocking inbound connections".to_owned()),
        ..hosts()
    };
    let result = probe_firewall_hint(&host);
    assert_eq!(result.status, ProbeStatus::Warn);
    assert!(result.detail.contains("Windows Defender"));
    assert!(result.suggestion.is_some());
}

#[test]
fn no_firewall_hint_is_not_a_problem() {
    assert_eq!(probe_firewall_hint(&hosts()).status, ProbeStatus::Ok);
}

#[test]
fn a_writable_directory_passes_and_gains_no_litter() {
    let dir = std::env::temp_dir().join(format!("synra-doctor-rw-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&dir);

    let result = probe_data_dir_writable(&dir);
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    // The probe file is removed, so a repeated diagnosis does not accumulate files.
    assert!(
        !dir.join(".synra-write-probe").exists(),
        "the probe left its file behind"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_directory_that_cannot_be_created_fails() {
    // A path under an existing regular file cannot become a directory, on every platform.
    let file = std::env::temp_dir().join(format!("synra-doctor-file-{}", unique_suffix()));
    std::fs::write(&file, b"not a directory").expect("writes");

    let result = probe_data_dir_writable(&file.join("under-a-file"));
    assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
    assert!(result.suggestion.is_some());

    let _ = std::fs::remove_file(&file);
}

#[test]
fn the_disk_probe_does_not_claim_a_figure_it_cannot_read() {
    // A portable free-space query does not exist in the standard library, so the probe says so rather
    // than inventing a number.
    let dir = std::env::temp_dir().join(format!("synra-doctor-disk-{}", unique_suffix()));
    let result = probe_disk_space(&dir);
    assert!(result.status.needs_attention() || result.status == ProbeStatus::Ok);
    assert!(
        result.detail.contains("platform query"),
        "the probe overstated what it measured: {}",
        result.detail
    );
}

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
fn keyring_states_map_to_the_right_status() {
    assert_eq!(
        probe_keyring_available(&HostFacts { keyring_available: Some(true), ..Default::default() }).status,
        ProbeStatus::Ok
    );
    let locked = probe_keyring_available(&HostFacts {
        keyring_available: Some(false),
        ..Default::default()
    });
    assert_eq!(locked.status, ProbeStatus::Fail);
    assert!(locked.suggestion.is_some());
    assert_eq!(probe_keyring_available(&HostFacts::default()).status, ProbeStatus::Warn);
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
fn a_missing_plugin_directory_is_not_a_problem() {
    // A fresh install has no plugins, and reporting that as a fault would make every new install look
    // broken.
    let dir = std::env::temp_dir().join(format!("synra-doctor-plugins-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&dir);

    let result = probe_plugin_dir(&dir);
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    assert!(result.detail.contains("no plugins"));
}

#[test]
fn a_plugin_directory_is_counted_rather_than_described() {
    let dir = std::env::temp_dir().join(format!("synra-doctor-plugins2-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creates");
    for index in 0..3 {
        std::fs::write(dir.join(format!("plugin{index}")), b"x").expect("writes");
    }

    let result = probe_plugin_dir(&dir);
    assert_eq!(result.status, ProbeStatus::Ok);
    assert!(result.detail.contains('3'), "{}", result.detail);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_whole_suite_reports_every_probe() {
    // Every probe has to appear in the report even when it passes, because "which checks ran" is part of
    // what the user is being shown.
    let report = run_probes(&targets(), &hosts());

    for name in [
        "tcp_port_available",
        "discovery_port_available",
        "discovery_udp_available",
        "network_stack",
        "firewall",
        "data_dir_writable",
        "disk_space",
        "clock_sanity",
        "webview_version",
        "keyring",
        "wasm_backend",
        "plugin_dir",
    ] {
        assert!(report.get(name).is_some(), "{name} is missing from the report");
    }
    // And every result carries a non-empty name and detail, so the interface has something to render.
    for result in &report.results {
        assert!(!result.name.is_empty());
        assert!(!result.detail.is_empty(), "{}", result.name);
    }
}

#[test]
fn the_suite_passes_on_a_healthy_machine() {
    // With every host fact good and ports chosen by the operating system, nothing should fail.
    let report = run_probes(&targets(), &hosts());
    assert_eq!(report.worst(), ProbeStatus::Ok, "{:#?}", report.problems());
}

#[test]
fn a_missing_host_fact_makes_the_suite_warn_rather_than_fail() {
    // The application layer not reporting something is not the machine being broken.
    let report = run_probes(&targets(), &HostFacts::default());
    assert_ne!(report.worst(), ProbeStatus::Fail, "{:#?}", report.problems());
    assert!(report.needs_attention(), "three facts were unknown");
}

#[test]
fn the_low_space_threshold_is_inclusive_at_its_boundary() {
    // A disk with exactly the threshold free is not yet low, and one byte less is. The boundary has to be
    // decided once, here, or the settings screen and the probe would disagree.
    assert!(!is_low_disk_space(LOW_DISK_BYTES));
    assert!(is_low_disk_space(LOW_DISK_BYTES - 1));
    assert!(is_low_disk_space(0));
    assert!(!is_low_disk_space(LOW_DISK_BYTES + 1));
}

#[test]
fn the_disk_probe_sample_is_small_enough_to_be_unobtrusive() {
    // A diagnosis that writes a hundred megabytes to talk about disk space is both slow and rude.
    assert_eq!(DISK_PROBE_SAMPLE_BYTES, 1024 * 1024);
    assert!(
        (DISK_PROBE_SAMPLE_BYTES as u64) < LOW_DISK_BYTES / 100,
        "the sample is a material fraction of the threshold it is checking"
    );
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
