//! Resolves plugin paths against a canonical sandbox root.

use std::path::{Path, PathBuf};

use crate::paths::{PathError, is_within};

use super::{PluginDataRoot, SUBDIRECTORIES};

impl PluginDataRoot {
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

    /// Whether a resolved path is inside this sandbox.
    ///
    /// For a caller that has a path from elsewhere — a stored reference, a message — and wants to check it
    /// before using it. Returns `false` for anything it cannot compare rather than guessing.
    #[must_use]
    pub fn contains(&self, candidate: &Path) -> bool {
        is_within(&self.root, candidate)
    }
}
