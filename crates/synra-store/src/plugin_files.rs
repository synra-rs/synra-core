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
mod tests {
    use super::*;

    /// A layout under a directory nobody else uses, removed when the test ends.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-pf-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        fn paths(&self) -> Paths {
            Paths::new(self.0.join("data"), self.0.join("cache"))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fill(path: &Path) {
        std::fs::create_dir_all(path).expect("a directory");
        std::fs::write(path.join("plugin.wasm"), b"\0asm").expect("a file");
    }

    #[test]
    fn artifacts_go_and_data_stays_by_default() {
        // ★ The default is the whole point: a user who uninstalls a plugin they may reinstall keeps its settings, and
        // deleting them unless asked would be the interface deciding what is replaceable.
        let scratch = Scratch::new("default");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));
        fill(&paths.plugin_sandbox_dir("@acme/hello"));

        let removal = PluginFiles::new(paths.clone())
            .remove("@acme/hello", false)
            .expect("removes");

        assert!(removal.leftovers.is_empty(), "nothing was held back");
        assert_eq!(removal.bytes_freed, 4, "the artifact's four bytes");
        assert!(!paths.plugin_dir("@acme/hello").exists(), "artifacts are gone");
        assert!(paths.plugin_sandbox_dir("@acme/hello").exists(), "data is kept");
    }

    #[test]
    fn asking_for_the_data_removes_it_too() {
        let scratch = Scratch::new("data");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));
        fill(&paths.plugin_sandbox_dir("@acme/hello"));

        let removal = PluginFiles::new(paths.clone())
            .remove("@acme/hello", true)
            .expect("removes");

        assert!(removal.leftovers.is_empty(), "nothing was held back: {:?}", removal.leftovers);
        assert_eq!(removal.bytes_freed, 8, "artifact and sandbox");
        assert!(!paths.plugin_dir("@acme/hello").exists());
        assert!(!paths.plugin_sandbox_dir("@acme/hello").exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_locked_file_is_reported_as_a_leftover_rather_than_failing() {
        // ★ A loaded engine keeps its wasm file open on Windows, and a deletion then fails. The row is already gone, so
        // refusing would leave the files behind and say nothing; the leftover list is how the caller tells the user.
        use std::os::windows::fs::OpenOptionsExt as _;

        let scratch = Scratch::new("locked");
        let paths = scratch.paths();
        let directory = paths.plugin_dir("@acme/hello");
        fill(&directory);
        // Share mode zero: no other open — including the one a removal needs — may touch the file.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(directory.join("plugin.wasm"))
            .expect("an exclusive handle");

        let removal = PluginFiles::new(paths.clone())
            .remove("@acme/hello", false)
            .expect("the refusal is reported, not thrown");
        assert_eq!(removal.leftovers, vec![directory.clone()], "the directory that survived");
        // ★ And the number does not lie: the directory is still on disk, so nothing was freed.
        assert_eq!(removal.bytes_freed, 0, "a surviving directory frees no space");
        assert!(directory.exists(), "the files are still there, as reported");

        drop(held);
        let removal = PluginFiles::new(paths).remove("@acme/hello", false).expect("removes");
        assert!(removal.leftovers.is_empty(), "a later attempt finishes the job");
        assert_eq!(removal.bytes_freed, 4, "the bytes go when the files do");
    }

    #[test]
    fn a_second_removal_is_not_an_error() {
        // "This plugin should not be here" is satisfied by a directory that is not there.
        let scratch = Scratch::new("twice");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));

        PluginFiles::new(paths.clone()).remove("@acme/hello", false).expect("first");
        let second = PluginFiles::new(paths).remove("@acme/hello", false).expect("second");
        assert_eq!(second.bytes_freed, 0, "there was nothing left to free");
    }

    #[test]
    fn the_size_is_the_artifacts_and_the_data_when_asked() {
        // ★ Measured before the removal, and only the data when it is going: the number is what a user is told a removal
        // frees, so counting a sandbox that stays would be telling them they got space back they did not.
        let scratch = Scratch::new("size");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));
        fill(&paths.plugin_sandbox_dir("@acme/hello"));
        let files = PluginFiles::new(paths);

        assert_eq!(files.size_of("@acme/hello", false), 4, "the artifact's four bytes");
        assert_eq!(files.size_of("@acme/hello", true), 8, "artifact and sandbox");
        assert_eq!(files.size_of("@acme/absent", true), 0, "a directory that is not there");
    }

    #[test]
    fn a_sweep_takes_orphan_artifacts_and_leaves_everything_else() {
        // ★ The second chance a leftover gets: the row is gone, so the artifact directory is trash no later code can
        // reach. The sandbox is not — data kept on purpose is a user's settings — and a stray file in the artifact root is
        // somebody else's business.
        let scratch = Scratch::new("sweep");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));
        fill(&paths.plugin_dir("@acme/orphan"));
        fill(&paths.plugin_sandbox_dir("@acme/orphan"));
        std::fs::write(paths.plugins_dir().join("README"), b"keep").expect("a stray file");

        let sweep = PluginFiles::new(paths.clone())
            .sweep_orphans(&["@acme/hello".to_owned()])
            .expect("sweeps");

        assert_eq!(sweep.removed, vec![paths.plugin_dir("@acme/orphan")]);
        assert_eq!(sweep.bytes_freed, 4, "the orphan's artifact bytes, not its data");
        assert!(sweep.leftovers.is_empty());
        assert!(paths.plugin_dir("@acme/hello").exists(), "an installed plugin is not touched");
        assert!(!paths.plugin_dir("@acme/orphan").exists());
        assert!(
            paths.plugin_sandbox_dir("@acme/orphan").exists(),
            "data is kept until the user says otherwise"
        );
        assert!(paths.plugins_dir().join("README").exists(), "a file is not a directory");
    }

    #[cfg(windows)]
    #[test]
    fn a_sweep_reports_an_orphan_it_still_cannot_remove() {
        use std::os::windows::fs::OpenOptionsExt as _;

        let scratch = Scratch::new("sweep-locked");
        let paths = scratch.paths();
        let directory = paths.plugin_dir("@acme/orphan");
        fill(&directory);
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(directory.join("plugin.wasm"))
            .expect("an exclusive handle");

        let sweep = PluginFiles::new(paths.clone())
            .sweep_orphans(&[])
            .expect("the sweep reports rather than throws");
        assert_eq!(sweep.removed, Vec::<std::path::PathBuf>::new());
        assert_eq!(sweep.leftovers, vec![directory]);
        assert_eq!(sweep.bytes_freed, 0, "nothing left the disk");

        drop(held);
        let sweep = PluginFiles::new(paths).sweep_orphans(&[]).expect("sweeps");
        assert_eq!(sweep.bytes_freed, 4, "the next start finishes the job");
        assert!(sweep.leftovers.is_empty());
    }
}
