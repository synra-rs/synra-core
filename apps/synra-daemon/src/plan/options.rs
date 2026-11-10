use std::path::PathBuf;

/// The port the main transport listens on by default.
pub const DEFAULT_LISTEN_PORT: u16 = 47_100;

/// The port discovery listens on by default.
///
/// # Why this is the protocol's constant and not a number of its own
///
/// Because discovery only works if every device listens in the same place. The first version of this was `47_101`, chosen
/// to sit next to the transport port — and it was **wrong twice over**: nothing ever bound it, because the discovery
/// socket used the protocol's `32101` regardless, and a device that had actually honoured `47_101` would have been
/// invisible to every device using the protocol's port.
///
/// The constant is *referenced* rather than repeated, so the flag, the socket and the protocol cannot drift apart again.
pub const DEFAULT_DISCOVERY_PORT: u16 = synra_protocol::limits::DISCOVERY_PORT;

/// How the daemon was asked to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOptions {
    /// Where the data lives.
    pub data_dir: PathBuf,
    /// The transport port.
    pub listen_port: u16,
    /// The discovery port.
    pub discovery_port: u16,
    /// Whether to claim the data directory exclusively.
    ///
    /// On by default, because two daemons over one database is a correctness problem rather than a performance one.
    /// Off is for a diagnostic run against a live installation: a user who wants to see what a running daemon thinks
    /// should not have to stop it.
    pub exclusive: bool,
    /// Whether to keep running when the last client disconnects.
    ///
    /// On: a daemon whose purpose is to keep serving after the interface closes must not exit the moment the
    /// interface does. It is a flag rather than a constant because the opposite is what a user wants when running one
    /// from a terminal to watch it.
    pub linger: bool,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            data_dir: default_data_root(),
            listen_port: DEFAULT_LISTEN_PORT,
            discovery_port: DEFAULT_DISCOVERY_PORT,
            exclusive: true,
            linger: true,
        }
    }
}

/// Where the daemon looks when nothing says otherwise.
///
/// The same answer the CLI gives, from the same environment variable, so that `synra doctor` checks the installation
/// the daemon actually uses. A `doctor` that probed a different directory would report a healthy installation on a
/// machine whose real one is broken, which is the worst answer a diagnostic tool can give.
#[must_use]
pub fn default_data_root() -> PathBuf {
    data_root_from(std::env::var_os(DATA_DIR_VAR))
}

/// The environment variable that moves the data directory.
pub const DATA_DIR_VAR: &str = "SYNRA_DATA_DIR";

/// The data root for a given value of the environment variable.
///
/// The value is a parameter because reading an environment variable is not testable from inside a process:
/// `std::env::set_var` is `unsafe` in edition 2024, and this workspace forbids `unsafe`. So the decision takes its
/// input and the caller reads it.
#[must_use]
pub fn data_root_from(configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("synra"),
    }
}
