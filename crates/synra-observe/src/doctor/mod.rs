//! Environment diagnosis: the eleven checks behind `synra doctor` and the settings screen.
//!
//! # What this is for
//!
//! Most support conversations start with a question the user cannot answer: which port is in use, whether
//! the disk is full, whether the system clock is weeks out and quietly breaking every timeout. A probe
//! answers it in code and reports three things — what it checked, what it found, and what to do about it.
//!
//! The third is the one that matters. "Port 32100 is in use by another process" is information; "close the
//! other copy of Synra, or change the port in Settings → Network" is a fix.
//!
//! # Every probe says which of the three it is
//!
//! * [`ProbeStatus::Ok`] — nothing to do.
//! * [`ProbeStatus::Warn`] — it works, and it will probably bite later. A disk with 400 MB free is a warning
//!   now and a failure in an hour.
//! * [`ProbeStatus::Fail`] — something will not work.
//!
//! A probe that cannot reach a conclusion reports `Warn` rather than `Fail`. `Fail` is a claim that the
//! feature is broken; not being able to tell is not the same claim, and a diagnostic that cries wolf is one
//! people learn to ignore.
//!
//! # Probes that need the host are injected
//!
//! A keyring, a WebView version and a firewall hint are different on every platform and only knowable from
//! the application layer. They arrive as a [`HostFacts`] value rather than as calls into Tauri, so the whole
//! probe suite is testable without a window, a keychain or a network stack.

mod host;
mod network;
mod result;
mod storage;
mod targets;

pub use host::{
    MAX_CLOCK_SKEW_SECS, MIN_WEBVIEW_MAJOR, clock_skew_within_tolerance, probe_clock_sanity,
    probe_keyring_available, probe_wasm_backend, probe_webview_version,
};
pub use network::{
    probe_firewall_hint, probe_network_interfaces, probe_port_available, probe_udp_port_available,
};
pub use result::{ProbeReport, ProbeResult, ProbeStatus};
pub use storage::{
    DISK_PROBE_SAMPLE_BYTES, LOW_DISK_BYTES, is_low_disk_space, probe_data_dir_writable,
    probe_disk_space, probe_plugin_dir,
};
pub use targets::{HostFacts, ProbeTargets};

/// Runs every probe.
///
/// Synchronous: a probe is a `bind`, a `statfs` or an environment read, all of which finish immediately, and
/// making the suite `async` would push that decision onto every caller for no benefit.
#[must_use]
pub fn run_probes(targets: &ProbeTargets, host: &HostFacts) -> ProbeReport {
    let mut report = ProbeReport::new();
    report.push(probe_port_available("tcp_port_available", targets.listen_port));
    report.push(probe_port_available("discovery_port_available", targets.discovery_port));
    report.push(probe_udp_port_available(targets.discovery_port));
    report.push(probe_network_interfaces());
    report.push(probe_firewall_hint(host));
    report.push(probe_data_dir_writable(&targets.data_dir));
    report.push(probe_disk_space(&targets.data_dir));
    report.push(probe_clock_sanity());
    report.push(probe_webview_version(host));
    report.push(probe_keyring_available(host));
    report.push(probe_wasm_backend(host));
    report.push(probe_plugin_dir(&targets.plugins_dir));
    report
}

#[cfg(test)]
mod tests;
