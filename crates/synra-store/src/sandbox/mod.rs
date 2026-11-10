//! The plugin data sandbox: resolving a plugin's paths without letting it out.
//!
//! # Why this is not "resolve, check the prefix, then open"
//!
//! That three-step pattern is the obvious implementation and it has a window: between the check and the open,
//! a component of the path can be replaced with a symlink. The attacker does not need a race to be reliable —
//! a plugin can create the symlink itself, wait, and try again — and the failure is a plugin reading the user's
//! files through a path it was authorised to use.
//!
//! So the check here is done by **canonicalising and then comparing**, in one place, and the result is returned
//! as a resolved path rather than a verdict. A caller cannot check and then open something else, because there
//! is no API that takes a raw path and a sandbox separately.
//!
//! The ideal is stronger still: `cap-std`'s directory handles, where every operation goes through a file
//! descriptor that was opened once and cannot be redirected. That needs a dependency, and this crate's job is
//! to be checkable without one; the design document names `cap-std` as the target, and this module's shape — a
//! resolved root and subdirectory handles — is what makes that swap a local change.
//!
//! # The three things a plugin may not do
//!
//! * **Absolute paths.** `/etc/passwd` is not relative to the sandbox, and joining an absolute path onto a
//!   prefix is not an error in any of the languages people reach for: `Path::join` replaces rather than appends.
//! * **Leave through `..`.** Rejected after canonicalisation rather than by counting the `..`s, because a
//!   symlink inside the sandbox can point out of it and counting cannot see that.
//! * **Name a directory that is not one of its roots.** `files/` and `cache/` are the two; anything else is not
//!   a mistyped path, it is a plugin asking for a directory that was never promised to it.
//!
//! # The metrics file is the user's view of the sandbox
//!
//! `files/` is what the settings screen shows as "this plugin is using 12 MB", which is what makes the size
//! question answerable and the data removable. So the sandbox records what it knows and the interface reads
//! that, rather than each of them counting bytes a different way.

use std::path::{Path, PathBuf};

use crate::paths::{PathError, is_within, sanitise_component};

/// The subdirectories a plugin may name.
///
/// A closed list. `files` is durable and user-visible; `cache` may be deleted at any time, including while the
/// plugin is running, which is what the name promises.
pub const SUBDIRECTORIES: &[&str] = &["files", "cache"];

/// The durable, user-visible subdirectory.
pub const FILES: &str = "files";

/// The disposable subdirectory.
pub const CACHE: &str = "cache";

mod meta;

pub use meta::SandboxMeta;

/// One plugin's data root.
///
/// Holds a canonicalised path, so every resolution starts from something the filesystem has already agreed
/// about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDataRoot {
    root: PathBuf,
    plugin_id: String,
}

impl PluginDataRoot {
    /// Creates the sandbox and returns its canonicalised root.
    ///
    /// # Errors
    ///
    /// [`PathError::Unwritable`] or [`PathError::Unresolvable`].
    pub fn ensure(parent: &Path, plugin_id: &str) -> Result<Self, PathError> {
        let root = parent.join(sanitise_component(plugin_id));
        std::fs::create_dir_all(&root).map_err(|source| PathError::Unwritable {
            path: root.display().to_string(),
            detail: source.to_string(),
        })?;

        for subdirectory in SUBDIRECTORIES {
            let directory = root.join(subdirectory);
            std::fs::create_dir_all(&directory).map_err(|source| PathError::Unwritable {
                path: directory.display().to_string(),
                detail: source.to_string(),
            })?;
        }

        // Canonicalised once, here. Every later comparison is against this value, so a symlinked parent — a
        // user who moved their data directory and linked it back — does not make every resolution fail.
        let canonical = std::fs::canonicalize(&root).map_err(|source| PathError::Unresolvable {
            path: root.display().to_string(),
            detail: source.to_string(),
        })?;

        Ok(Self {
            root: canonical,
            plugin_id: plugin_id.to_owned(),
        })
    }

    /// A root that is assumed to exist, for a caller that has already created it.
    ///
    /// # Errors
    ///
    /// [`PathError::Unresolvable`] if the path cannot be canonicalised.
    pub fn open(root: &Path, plugin_id: &str) -> Result<Self, PathError> {
        let canonical = std::fs::canonicalize(root).map_err(|source| PathError::Unresolvable {
            path: root.display().to_string(),
            detail: source.to_string(),
        })?;
        Ok(Self {
            root: canonical,
            plugin_id: plugin_id.to_owned(),
        })
    }

    /// The canonicalised root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The plugin this sandbox belongs to.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The canonicalised path of one of the two subdirectories.
    ///
    /// # Errors
    ///
    /// [`PathError::BadComponent`] if the name is not one of [`SUBDIRECTORIES`].
    pub fn subdirectory(&self, name: &str) -> Result<PathBuf, PathError> {
        if !SUBDIRECTORIES.contains(&name) {
            return Err(PathError::BadComponent {
                path: name.to_owned(),
                component: format!("a plugin may name only {}", SUBDIRECTORIES.join(" or ")),
            });
        }
        let path = self.root.join(name);
        // Present because `ensure` created it. A caller that deleted it gets the error rather than a path that
        // does not exist, which is the difference between a clear failure and a confusing one later.
        std::fs::canonicalize(&path).map_err(|source| PathError::Unresolvable {
            path: path.display().to_string(),
            detail: source.to_string(),
        })
    }

    /// Resolves a plugin-supplied relative path inside a subdirectory.
    ///
    /// This is the function a plugin's `fs:read` and `fs:write` calls go through.
    ///
    /// # Errors
    ///
    /// * [`PathError::Absolute`] if the path starts at the root of the filesystem.
    /// * [`PathError::BadComponent`] if it names a subdirectory that is not one of the two.
    /// * [`PathError::Escapes`] if it resolves outside the subdirectory — through `..`, or through a symlink
    ///   that points out.
    /// * [`PathError::Unresolvable`] if the parent cannot be resolved.
    ///
    /// # Resolving the parent, not the file
    ///
    /// A file being *created* does not exist yet, so canonicalising the whole path would fail for every write.
    /// The parent is canonicalised — that is the part that carries the escape risk — and the file name is
    /// joined onto the result, so the returned path is inside a directory that was verified.
    pub fn resolve(&self, subdirectory: &str, relative: &str) -> Result<PathBuf, PathError> {
        let base = self.subdirectory(subdirectory)?;

        let relative_path = Path::new(relative);
        if relative_path.is_absolute() {
            return Err(PathError::Absolute(relative.to_owned()));
        }

        // A drive-relative path on Windows, such as `C:foo`, is neither absolute nor relative in the way this
        // function means, and `join` would replace the base with it.
        if relative_path
            .components()
            .any(|component| matches!(component, std::path::Component::Prefix(_)))
        {
            return Err(PathError::Absolute(relative.to_owned()));
        }

        // The deepest component has to be a plain name: `.` or `..` as the last component names a directory
        // rather than a file, and accepting it would make `create` open something the caller did not mean.
        let Some(file_name) = relative_path.file_name() else {
            return Err(PathError::BadComponent {
                path: relative.to_owned(),
                component: "a path must name a file".to_owned(),
            });
        };

        let parent = relative_path.parent().unwrap_or(Path::new(""));
        let joined_parent = base.join(parent);

        // Canonicalising the parent is what catches a symlink pointing out of the sandbox: `..` alone could be
        // counted, but a symlink cannot, and a plugin can create one because it can write to `files/`.
        let canonical_parent =
            std::fs::canonicalize(&joined_parent).map_err(|source| PathError::Unresolvable {
                path: joined_parent.display().to_string(),
                detail: source.to_string(),
            })?;

        if !is_within(&base, &canonical_parent) {
            return Err(PathError::Escapes {
                path: relative.to_owned(),
                root: base.display().to_string(),
            });
        }

        Ok(canonical_parent.join(file_name))
    }

    /// Measures how much the plugin is using.
    ///
    /// # Errors
    ///
    /// [`PathError::Unresolvable`] if a subdirectory cannot be read.
    pub fn measure(&self, measured_at_ms: i64) -> Result<SandboxMeta, PathError> {
        let mut meta = SandboxMeta::new(&self.plugin_id, measured_at_ms);
        meta.files_bytes = self.measure_subdirectory(FILES)?;
        meta.cache_bytes = self.measure_subdirectory(CACHE)?;
        Ok(meta)
    }

    /// Measures one subdirectory.
    fn measure_subdirectory(&self, name: &str) -> Result<u64, PathError> {
        let directory = self.root.join(name);
        let mut total = 0u64;
        // `directory` itself is the walk's starting point, so nothing is cloned: the error is reported from the
        // directory the caller asked about, which is the one the stack holds.
        let mut stack: Vec<PathBuf> = vec![directory];

        while let Some(current) = stack.pop() {
            let entries =
                std::fs::read_dir(&current).map_err(|source| PathError::Unresolvable {
                    path: current.display().to_string(),
                    detail: source.to_string(),
                })?;
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                // `symlink_metadata` rather than `metadata`: a symlink's own size is what it occupies, and
                // following one would let a plugin point at a large file elsewhere and claim the space.
                let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if metadata.is_dir() {
                    stack.push(path);
                } else {
                    total = total.saturating_add(metadata.len());
                }
            }
        }
        Ok(total)
    }

    /// Removes the cache.
    ///
    /// # Errors
    ///
    /// [`PathError::Unwritable`] if something in it cannot be removed.
    ///
    /// # The directory is recreated
    ///
    /// The plugin may be running. Deleting `cache/` itself would leave the next `resolve` failing on a missing
    /// directory, which reads as a sandbox problem rather than as a cache that was cleared — so the directory
    /// is made again immediately.
    pub fn clear_cache(&self) -> Result<(), PathError> {
        let cache = self.root.join(CACHE);
        if cache.exists() {
            std::fs::remove_dir_all(&cache).map_err(|source| PathError::Unwritable {
                path: cache.display().to_string(),
                detail: source.to_string(),
            })?;
        }
        std::fs::create_dir_all(&cache).map_err(|source| PathError::Unwritable {
            path: cache.display().to_string(),
            detail: source.to_string(),
        })
    }

    /// Removes everything the plugin owns.
    ///
    /// # Errors
    ///
    /// [`PathError::Unwritable`] if something cannot be removed.
    pub fn remove_all(&self) -> Result<(), PathError> {
        std::fs::remove_dir_all(&self.root).map_err(|source| PathError::Unwritable {
            path: self.root.display().to_string(),
            detail: source.to_string(),
        })
    }

    /// Whether a resolved path is inside this sandbox.
    ///
    /// For a caller that has a path from elsewhere — a stored reference, a message — and wants to check it
    /// before using it. Returns `false` for anything it cannot compare rather than guessing.
    #[must_use]
    pub fn contains(&self, candidate: &Path) -> bool {
        is_within(&self.root, candidate)
    }
}

#[cfg(test)]
mod tests;
