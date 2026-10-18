//! Installing, with the daemon's capabilities.
//!
//! The pipeline is [`synra_core::install`] — the checks, the staging layout, the rollback and the row. What is here is
//! the one thing a host decides: what this machine can do, which is what the platform-applicability check reads. A
//! daemon has no window, so a plugin that declares a notification earns a warning here and none on the desktop shell.
//!
//! # Why a wrapper rather than a second implementation
//!
//! Because the order of the checks is the security argument, and two hosts each running their own copy of it would be
//! two places for that order to drift. The Tauri shell calls the same function with [`HostFacts::desktop()`].

use std::path::Path;

// Re-exported rather than imported: the daemon's command layer names these two types, and a caller that had to spell
// `synra_core::install::…` would be naming the pipeline it is not calling directly.
pub use synra_core::install::{InstallRefusal, Installed};
use synra_plugin_host::Backend;
use synra_plugin_host::verify::HostFacts;

/// Installs the plugin in `source` into `plugins_dir`, after verifying it.
///
/// # Errors
///
/// [`InstallRefusal`] naming the step that refused. Nothing is written to `plugins_dir` and no row is recorded unless
/// every check passed and the copy completed.
pub fn from_directory(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
) -> Result<Installed, InstallRefusal> {
    synra_core::install::from_directory(db, backend, plugins_dir, source, now_ms, HostFacts::headless())
}

#[cfg(test)]
mod tests;
