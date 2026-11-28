use std::path::Path;

use synra_plugin_host::Backend;
use synra_plugin_host::verify::HostFacts;

use super::{InstallRefusal, Installed, writing};

mod prepare;

pub(crate) use prepare::{Prepared, prepare};

/// Installs the plugin in `source` into `plugins_dir`, after verifying it.
///
/// `host` is what the installing machine can do, and it is a parameter rather than a constant because the two hosts
/// differ: the daemon has no window, so a plugin that declares a notification gets a warning here and none on the
/// desktop shell. Nothing else about the pipeline changes with it.
///
/// # Errors
///
/// [`InstallRefusal`] naming the step that refused. Nothing is written to `plugins_dir` and no row is recorded unless
/// every check passed and the copy completed.
///
/// # Why the database is `&mut`
///
/// Because the install writes **two** rows that must undo together: the plugin and the version now in effect. The second
/// write can fail after the first succeeded, and the rollback removes the row as well as the directory — a plugin row
/// naming discarded files is what the loader reports as a broken plugin rather than as a failed install.
pub fn from_directory(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    from_directory_inner(db, backend, plugins_dir, source, now_ms, host, false)
}

/// Installs a newer version over the plugin already at that identifier.
///
/// # What is different from an install
///
/// Every check is the same — the package is verified completely before the old directory is touched — and only the final
/// two steps differ: the existing directory is moved aside, the new one takes its place, and the old one is removed once
/// the version row has landed. A failure at either step restores the old directory, so an update that cannot finish is an
/// update that did not happen rather than a plugin that is now half of each version.
///
/// # Errors
///
/// [`InstallRefusal`] as [`from_directory`], plus `update` when nothing is installed at that identifier.
pub fn update_from_directory(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    from_directory_inner(db, backend, plugins_dir, source, now_ms, host, true)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the pipeline's inputs, plus whether it replaces an installed copy"
)]
fn from_directory_inner(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
    replace: bool,
) -> Result<Installed, InstallRefusal> {
    let prepared = prepare(db, backend, source, now_ms, host, replace)?;
    let mode = if replace {
        writing::WriteMode::Replace
    } else {
        writing::WriteMode::Install
    };
    writing::write(db, plugins_dir, now_ms, prepared, mode)
}
