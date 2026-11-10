use super::super::{HostFacts, ProbeStatus, run_probes};
use super::{hosts, targets};

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
