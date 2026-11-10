//! Loading the plugins a host is supposed to be running.
//!
//! Loading is shared by every host. The engine is a host's own, but which installed plugins run and with what
//! authority is the kernel's answer. Every plugin is loaded independently so one broken artifact does not stop the
//! remaining plugins from starting.

mod discovery;
mod lifecycle;
mod loader;
mod model;

pub use discovery::{record_discovered_plugins, Discovered};
pub use lifecycle::{activation_config, deactivate, migrate, reactivate_loaded};
pub use loader::{
    load_installed, load_installed_with_config, load_plugin, load_plugin_with_config,
};
pub use model::{LoadedSummary, Refused};

/// How many instances one plugin may have.
pub const INSTANCE_LIMIT: u32 = 4;

#[cfg(test)]
mod tests;
