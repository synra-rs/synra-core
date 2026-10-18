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
    pub fn remove(&self, plugin_id: &str, remove_data: bool) -> Result<(), PathError> {
        self.remove_below(&self.paths.plugin_dir(plugin_id), &self.paths.plugins_dir())?;
        if remove_data {
            self.remove_below(&self.paths.plugin_sandbox_dir(plugin_id), &self.paths.plugin_data_dir())?;
        }
        Ok(())
    }

    /// Removes one tree, having checked it is where it claims to be.
    fn remove_below(&self, target: &Path, root: &Path) -> Result<(), PathError> {
        if !is_within(root, target) {
            return Err(PathError::Escapes {
                path: target.display().to_string(),
                root: root.display().to_string(),
            });
        }
        match std::fs::remove_dir_all(target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(PathError::Unwritable {
                path: target.display().to_string(),
                detail: error.to_string(),
            }),
        }
    }
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

        PluginFiles::new(paths.clone()).remove("@acme/hello", false).expect("removes");

        assert!(!paths.plugin_dir("@acme/hello").exists(), "artifacts are gone");
        assert!(paths.plugin_sandbox_dir("@acme/hello").exists(), "data is kept");
    }

    #[test]
    fn asking_for_the_data_removes_it_too() {
        let scratch = Scratch::new("data");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));
        fill(&paths.plugin_sandbox_dir("@acme/hello"));

        PluginFiles::new(paths.clone()).remove("@acme/hello", true).expect("removes");

        assert!(!paths.plugin_dir("@acme/hello").exists());
        assert!(!paths.plugin_sandbox_dir("@acme/hello").exists());
    }

    #[test]
    fn a_second_removal_is_not_an_error() {
        // "This plugin should not be here" is satisfied by a directory that is not there.
        let scratch = Scratch::new("twice");
        let paths = scratch.paths();
        fill(&paths.plugin_dir("@acme/hello"));

        PluginFiles::new(paths.clone()).remove("@acme/hello", false).expect("first");
        PluginFiles::new(paths).remove("@acme/hello", false).expect("second");
    }
}
