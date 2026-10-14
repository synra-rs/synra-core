//! What a probe is given: the paths and ports it inspects, and the facts only the host can supply.

use std::path::PathBuf;

/// What only the application layer can know.
///
/// Injected rather than queried, so the probe suite runs in a test with no window, no keychain and no
/// network stack.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    /// The WebView's version, when the host could read it.
    pub webview_version: Option<String>,
    /// Whether the platform keychain answered a test round trip.
    pub keyring_available: Option<bool>,
    /// Whether the Wasm runtime initialised.
    pub wasm_backend_available: Option<bool>,
    /// The platform's firewall advice, when there is any to give.
    pub firewall_hint: Option<String>,
}

/// What a probe needs to know about the installation.
#[derive(Debug, Clone)]
pub struct ProbeTargets {
    /// The directory the application writes its data to.
    pub data_dir: PathBuf,
    /// The directory plugins are installed under.
    pub plugins_dir: PathBuf,
    /// The port the main connection listens on.
    pub listen_port: u16,
    /// The port discovery listens on.
    pub discovery_port: u16,
}
