//! Environment probes and their reports.

use super::{HostFacts, ProbeTargets};

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
        wasm_backend_available: Some(true),
        firewall_hint: None,
    }
}

mod report;
mod network;
mod storage;
mod host;
mod plugins;
mod suite;
