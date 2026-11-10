//! The second owner of a directory tree: a plugin's artifacts, and its data when the user says so.
//!
//! # Why this exists at all
//!
//! `tools/guards` states that only the sandbox may delete a directory tree, and it was right: a recursive delete is the
//! operation that turns a path mistake into somebody's lost files. But uninstalling a plugin needs one, and the plugin's
//! artifact directory is **not** the sandbox's — the sandbox owns `plugin-data/`, this owns `plugins/`. The rule's own
//! answer is a second owner that says what it may delete, so this type exists rather than an exception.
//!
//! # What bounds it
//!
//! Three things, and each is one line of code rather than a promise:
//!
//! * the identifier is sanitised by [`Paths`] before it becomes a path;
//! * the target is checked to be inside the root ([`is_within`]) before anything is removed;
//! * the data directory is removed **only** when the caller asks, because data is the part a user cannot get back.
//!
//! # Why "already gone" is not an error
//!
//! Because the caller's intent is "this plugin should not be here", and a directory that is not there satisfies it. A
//! second uninstall reporting an error would send the interface to show a failure for a state nobody disputes.

use std::path::Path;

use crate::paths::{PathError, Paths, is_within};

/// Deletes a directory tree the caller owns, when it is inside `root`.
///
/// # Why a helper rather than a call in the installer
///
/// Because 11 §D2 names this file as one of the two places a tree may be removed, and an update's backup is a plugin
/// directory like any other: moving the operation here keeps the rule checkable instead of adding a second exception in
/// the kernel. The containment check is the same one [`PluginFiles::remove`] makes, for the same reason — a path mistake
/// must not become somebody else's lost files.
///
/// # Errors
///
/// [`std::io::ErrorKind::PermissionDenied`] when `path` is not inside `root`, and the filesystem's error when the tree
/// cannot be removed.
pub fn remove_tree(root: &Path, path: &Path) -> Result<(), PathError> {
    if !is_within(root, path) {
        return Err(PathError::Escapes {
            path: path.display().to_string(),
            root: root.display().to_string(),
        });
    }
    std::fs::remove_dir_all(path).map_err(|error| PathError::RemovalFailed {
        path: path.display().to_string(),
        detail: error.to_string(),
    })
}

/// What a removal actually did.
///
/// # Why the byte count is measured again on the way out
///
/// Because "how much was there" and "how much went" are different numbers the moment a directory cannot be removed. A
/// report that said the first would tell a user they freed space that is still occupied — and the leftover list beside it
/// would be the only thing contradicting the number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// Bytes that are no longer on disk: measured before, minus what the leftovers still hold.
    pub bytes_freed: u64,
    /// Paths that could not be removed, empty in the ordinary case.
    pub leftovers: Vec<std::path::PathBuf>,
}

/// What a sweep of orphaned artifact directories did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sweep {
    /// Directories that are gone.
    pub removed: Vec<std::path::PathBuf>,
    /// The bytes those directories held.
    pub bytes_freed: u64,
    /// Directories that still could not be removed.
    pub leftovers: Vec<std::path::PathBuf>,
}

/// Deletes a plugin's artifact directory, and its data directory when asked.
#[derive(Debug, Clone)]
pub struct PluginFiles {
    paths: Paths,
}

impl PluginFiles {
    /// Over a data directory layout.
    #[must_use]
    pub const fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Removes the plugin's artifacts, and its data when `remove_data` is true.
    ///
    /// # Errors
    ///
    /// [`PathError::Escapes`] when a computed target is outside the root it belongs to — unreachable through [`Paths`],
    /// and checked here so it stays unreachable if this type's callers change. [`PathError::Unwritable`] when the
    /// operating system refuses a removal.
    /// Deletes a plugin's artifact directory, and its data directory when asked.
    ///
    /// # Returns
    ///
    /// What actually went, and what could not be removed. A directory held open by the running process (a loaded engine
    /// keeps its wasm file open on Windows) is **reported rather than refused**: the caller has already taken the plugin
    /// out of the database, so a removal that stopped at the first locked file would leave the files behind **and** say
    /// nothing about them. `bytes_freed` subtracts what the leftovers still hold, so the number matches the disk.
    ///
    /// # Errors
    ///
    /// [`PathError::Escapes`] when a computed target is outside the root it belongs to — unreachable through [`Paths`],
    /// and checked here so it stays unreachable if this type's callers change. A filesystem refusal is a leftover, not an
    /// error: the one thing that must not happen is a refusal that hides what is still there.
    pub fn remove(&self, plugin_id: &str, remove_data: bool) -> Result<Removal, PathError> {
        let before = self.size_of(plugin_id, remove_data);
        let mut leftovers = Vec::new();
        self.remove_below(
            &self.paths.plugin_dir(plugin_id),
            &self.paths.plugins_dir(),
            &mut leftovers,
        )?;
        if remove_data {
            self.remove_below(
                &self.paths.plugin_sandbox_dir(plugin_id),
                &self.paths.plugin_data_dir(),
                &mut leftovers,
            )?;
        }
        let remaining: u64 = leftovers
            .iter()
            .map(|path| directory_size(path))
            .fold(0, u64::saturating_add);
        Ok(Removal { bytes_freed: before.saturating_sub(remaining), leftovers })
    }

    /// How many bytes a removal would free: the artifacts, plus the data when `remove_data` is true.
    ///
    /// Measured **before** [`PluginFiles::remove`], because after it there is nothing to measure. A directory that does not
    /// exist counts as zero, and an entry that cannot be read is skipped rather than failing the count: the number is a
    /// report, and a plugin whose sandbox is unreadable is still a plugin that can be removed.
    #[must_use]
    pub fn size_of(&self, plugin_id: &str, remove_data: bool) -> u64 {
        let mut total = directory_size(&self.paths.plugin_dir(plugin_id));
        if remove_data {
            total = total.saturating_add(directory_size(&self.paths.plugin_sandbox_dir(plugin_id)));
        }
        total
    }

    /// Removes artifact directories that no installed plugin owns.
    ///
    /// # Why this exists
    ///
    /// Because a removal can leave a directory behind — a loaded engine holds its wasm file open on Windows — and the
    /// plugin's row is gone, so nothing will ever refer to that directory again. The next start is the moment to finish
    /// the job: the process that held the files open is gone, and this host has not loaded a plugin yet. Without the sweep
    /// a leftover was a fact the user could only fix by hand.
    ///
    /// # What it will not touch
    ///
    /// The **data** directories. A plugin's data is kept on purpose when the user uninstalls without deleting it, so a
    /// sandbox directory with no row is a user's settings, not garbage. Only the artifact root is swept, and only
    /// directories in it: a stray file there is somebody else's business.
    ///
    /// # Errors
    ///
    /// [`PathError::Unresolvable`] when the artifact root cannot be listed. A directory that cannot be removed is a
    /// leftover in the answer, not an error — the sweep is best effort about files, exact about what it left.
    pub fn sweep_orphans(&self, installed: &[String]) -> Result<Sweep, PathError> {
        let root = self.paths.plugins_dir();
        let expected: std::collections::HashSet<std::path::PathBuf> =
            installed.iter().map(|id| self.paths.plugin_dir(id)).collect();
        let entries = std::fs::read_dir(&root).map_err(|error| PathError::Unresolvable {
            path: root.display().to_string(),
            detail: error.to_string(),
        })?;

        let mut sweep = Sweep::default();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || expected.contains(&path) {
                continue;
            }
            let held = directory_size(&path);
            let mut leftovers = Vec::new();
            self.remove_below(&path, &root, &mut leftovers)?;
            if leftovers.is_empty() {
                sweep.removed.push(path);
                sweep.bytes_freed = sweep.bytes_freed.saturating_add(held);
            }
            else {
                sweep.leftovers.extend(leftovers);
            }
        }
        Ok(sweep)
    }

    /// Removes one tree, having checked it is where it claims to be.
    fn remove_below(
        &self,
        target: &Path,
        root: &Path,
        leftovers: &mut Vec<std::path::PathBuf>,
    ) -> Result<(), PathError> {
        if !is_within(root, target) {
            return Err(PathError::Escapes {
                path: target.display().to_string(),
                root: root.display().to_string(),
            });
        }
        match std::fs::remove_dir_all(target) {
            Ok(()) => Ok(()),
            // A directory that is not there satisfies "this plugin should not be here".
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => {
                leftovers.push(target.to_path_buf());
                Ok(())
            }
        }
    }
}

/// The bytes under a directory, or zero when it cannot be read.
///
/// Recursive, because a plugin's artifact is a directory tree and a sandbox may have subdirectories of its own. Errors are
/// zero rather than a refusal: this number is shown to a user deciding about a removal, and a directory that cannot be
/// read is still a directory the removal can attempt.
fn directory_size(root: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => directory_size(&entry.path()),
            Ok(_) => entry.metadata().map_or(0, |metadata| metadata.len()),
            Err(_) => 0,
        })
        .fold(0, u64::saturating_add)
}

#[cfg(test)]
mod tests;
