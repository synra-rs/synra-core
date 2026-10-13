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

use serde::{Deserialize, Serialize};

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

/// What the sandbox records about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxMeta {
    /// The plugin the sandbox belongs to.
    pub plugin_id: String,
    /// Bytes used under `files/`, as of the last count.
    pub files_bytes: u64,
    /// Bytes used under `cache/`.
    pub cache_bytes: u64,
    /// When usage was last measured, in milliseconds since the epoch.
    pub measured_at_ms: i64,
}

impl SandboxMeta {
    /// An empty record for a plugin.
    #[must_use]
    pub fn new(plugin_id: impl Into<String>, measured_at_ms: i64) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            files_bytes: 0,
            cache_bytes: 0,
            measured_at_ms,
        }
    }

    /// Total bytes the plugin is using.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.files_bytes.saturating_add(self.cache_bytes)
    }

    /// Whether the cache may be cleared without losing data.
    ///
    /// Always, by the definition of the directory; the method exists so the interface does not have to encode
    /// that knowledge.
    #[must_use]
    pub const fn is_cache_disposable(&self) -> bool {
        true
    }
}

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

        Ok(Self { root: canonical, plugin_id: plugin_id.to_owned() })
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
        Ok(Self { root: canonical, plugin_id: plugin_id.to_owned() })
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
        let canonical_parent = std::fs::canonicalize(&joined_parent).map_err(|source| {
            PathError::Unresolvable {
                path: joined_parent.display().to_string(),
                detail: source.to_string(),
            }
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
            let entries = std::fs::read_dir(&current).map_err(|source| PathError::Unresolvable {
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
                }
                else {
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
mod tests {
    use super::*;

    fn unique_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// A sandbox in a fresh temporary directory.
    struct Fixture {
        parent: PathBuf,
        sandbox: PluginDataRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let parent = std::env::temp_dir().join(format!("synra-sandbox-{}", unique_suffix()));
            let _ = std::fs::remove_dir_all(&parent);
            let sandbox =
                PluginDataRoot::ensure(&parent, "@synra-plugin/chat").expect("creates the sandbox");
            Self { parent, sandbox }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.parent);
        }
    }

    #[test]
    fn ensuring_creates_both_subdirectories() {
        let fixture = Fixture::new();
        assert!(fixture.sandbox.root().is_dir());
        for name in SUBDIRECTORIES {
            assert!(
                fixture.sandbox.subdirectory(name).expect("resolves").is_dir(),
                "{name} was not created"
            );
        }
    }

    #[test]
    fn the_root_is_canonicalised_so_a_linked_parent_still_works() {
        // A user who moved their data directory and linked it back would otherwise have every resolution fail,
        // because the configured path and the real one differ.
        let fixture = Fixture::new();
        assert!(fixture.sandbox.root().is_absolute());
        assert_eq!(
            fixture.sandbox.root(),
            std::fs::canonicalize(fixture.parent.join("synra-plugin+chat")).expect("canonical")
        );
    }

    #[test]
    fn only_the_two_subdirectories_may_be_named() {
        let fixture = Fixture::new();
        assert!(fixture.sandbox.subdirectory("files").is_ok());
        assert!(fixture.sandbox.subdirectory("cache").is_ok());

        // Not a mistyped path: a directory that was never promised to the plugin.
        for name in ["", "..", "/", "keys", "files/../cache", "secrets"] {
            match fixture.sandbox.subdirectory(name) {
                Err(PathError::BadComponent { .. }) => {}
                other => panic!("{name:?} should not resolve, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_plain_relative_path_resolves_inside_its_subdirectory() {
        let fixture = Fixture::new();
        // The parent has to exist, because that is the part which is canonicalised and therefore the part that
        // carries the escape risk. A caller writing a file creates its directory first.
        std::fs::create_dir_all(fixture.sandbox.root().join(FILES).join("notes")).expect("creates");

        let resolved = fixture.sandbox.resolve(FILES, "notes/today.txt").expect("resolves");

        let files = std::fs::canonicalize(fixture.sandbox.root().join(FILES)).expect("canonical");
        assert!(resolved.starts_with(&files), "{}", resolved.display());
        assert!(resolved.ends_with("today.txt"));
    }

    #[test]
    fn a_path_at_the_top_of_a_subdirectory_resolves() {
        let fixture = Fixture::new();
        assert!(fixture.sandbox.resolve(FILES, "a.txt").is_ok());
        // An empty relative path names the directory, not a file, so it is refused rather than treated as "the
        // subdirectory itself" — which would make a write into it ambiguous.
        assert!(fixture.sandbox.resolve(FILES, "").is_err());
        assert!(fixture.sandbox.resolve(FILES, ".").is_err());
    }

    #[test]
    fn an_absolute_path_is_refused() {
        // `Path::join` replaces rather than appends, so this would not be an error without the check: it would
        // be a read of `/etc/passwd`.
        let fixture = Fixture::new();
        // A path on the current platform that is rooted: `/etc/passwd` is absolute on Unix and merely
        // drive-relative on Windows, so the fixture is built rather than written out.
        let rooted = if cfg!(windows) { "C:\\Windows\\System32" } else { "/etc/passwd" };
        for path in [rooted, "\\\\server\\share"] {
            assert!(
                matches!(fixture.sandbox.resolve(FILES, path), Err(PathError::Absolute(_))),
                "{path:?} should be refused"
            );
        }
    }

    #[test]
    fn a_traversal_is_refused() {
        let fixture = Fixture::new();
        // `..` from `files/` reaches the sandbox root, and one more reaches the parent directory.
        for path in ["../cache", "../x", "../../x", "a/../../x", "a/../../../etc/passwd"] {
            match fixture.sandbox.resolve(FILES, path) {
                Err(PathError::Escapes { .. }) | Err(PathError::Unresolvable { .. }) => {}
                other => panic!("{path:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_traversal_that_stays_inside_is_allowed() {
        // `files/a/../b.txt` is `files/b.txt`, which is inside. Refusing it would be an over-correction that
        // breaks plugins doing ordinary path arithmetic.
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.sandbox.root().join(FILES).join("a")).expect("creates");
        let resolved = fixture.sandbox.resolve(FILES, "a/../b.txt").expect("resolves");

        let files = std::fs::canonicalize(fixture.sandbox.root().join(FILES)).expect("canonical");
        assert!(resolved.starts_with(&files), "{}", resolved.display());
        assert!(resolved.ends_with("b.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_out_is_refused() {
        // The case that makes "count the `..`s" insufficient: a plugin can create a symlink inside its own
        // sandbox, and counting components cannot see where it points.
        let fixture = Fixture::new();
        let outside = fixture.parent.join("outside");
        std::fs::create_dir_all(&outside).expect("creates");
        std::fs::write(outside.join("secret.txt"), b"secret").expect("writes");

        let link = fixture.sandbox.root().join(FILES).join("escape");
        std::os::unix::fs::symlink(&outside, &link).expect("links");

        match fixture.sandbox.resolve(FILES, "escape/secret.txt") {
            Err(PathError::Escapes { .. }) => {}
            other => panic!("a symlink out of the sandbox should be refused, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_inside_is_allowed() {
        // A plugin laying out its own storage with links is ordinary use, and refusing it would be an
        // over-correction.
        let fixture = Fixture::new();
        let target = fixture.sandbox.root().join(FILES).join("real");
        std::fs::create_dir_all(&target).expect("creates");

        let link = fixture.sandbox.root().join(FILES).join("link");
        std::os::unix::fs::symlink(&target, &link).expect("links");

        assert!(fixture.sandbox.resolve(FILES, "link/x.txt").is_ok());
    }

    #[test]
    fn a_missing_parent_is_unresolvable_rather_than_accepted() {
        // The file's parent has to be canonicalised, so it has to exist. Accepting a missing parent would mean
        // returning a path that was never checked against the sandbox.
        let fixture = Fixture::new();
        assert!(matches!(
            fixture.sandbox.resolve(FILES, "no/such/directory/x.txt"),
            Err(PathError::Unresolvable { .. })
        ));
    }

    #[test]
    fn a_resolved_path_is_always_inside_the_sandbox() {
        // The invariant a caller relies on, asserted over every shape a path can take.
        let fixture = Fixture::new();
        let candidates = [
            "a.txt",
            "a/b/c.txt",
            "a/../b.txt",
            "./a.txt",
            "a/./b.txt",
            "a//b.txt",
        ];
        for candidate in candidates {
            if let Ok(resolved) = fixture.sandbox.resolve(FILES, candidate) {
                assert!(
                    fixture.sandbox.contains(&resolved),
                    "{candidate:?} resolved outside the sandbox to {}",
                    resolved.display()
                );
            }
        }
    }

    #[test]
    fn containing_a_path_compares_against_the_root() {
        let fixture = Fixture::new();
        assert!(fixture.sandbox.contains(&fixture.sandbox.root().join("files/x")));
        assert!(fixture.sandbox.contains(fixture.sandbox.root()));
        // A sibling plugin's sandbox is not this one's, even sharing a prefix.
        assert!(!fixture.sandbox.contains(&fixture.parent.join("synra-plugin+notes/files/x")));
        assert!(!fixture.sandbox.contains(Path::new("/etc")));
    }

    #[test]
    fn measuring_counts_both_subdirectories() {
        let fixture = Fixture::new();
        let files = fixture.sandbox.root().join(FILES);
        let cache = fixture.sandbox.root().join(CACHE);
        std::fs::write(files.join("a.txt"), vec![b'x'; 100]).expect("writes");
        std::fs::create_dir_all(files.join("nested")).expect("creates");
        std::fs::write(files.join("nested/b.txt"), vec![b'x'; 50]).expect("writes");
        std::fs::write(cache.join("c.bin"), vec![b'x'; 25]).expect("writes");

        let meta = fixture.sandbox.measure(1_000).expect("measures");
        assert_eq!(meta.files_bytes, 150);
        assert_eq!(meta.cache_bytes, 25);
        assert_eq!(meta.total_bytes(), 175);
        assert_eq!(meta.plugin_id, "@synra-plugin/chat");
        assert_eq!(meta.measured_at_ms, 1_000);
        assert!(meta.is_cache_disposable());
    }

    #[test]
    fn measuring_an_empty_sandbox_reports_zero() {
        let fixture = Fixture::new();
        let meta = fixture.sandbox.measure(0).expect("measures");
        assert_eq!(meta.total_bytes(), 0);
    }

    #[test]
    fn clearing_the_cache_leaves_the_data_and_recreates_the_directory() {
        let fixture = Fixture::new();
        let files = fixture.sandbox.root().join(FILES);
        let cache = fixture.sandbox.root().join(CACHE);
        std::fs::write(files.join("keep.txt"), b"keep").expect("writes");
        std::fs::write(cache.join("drop.bin"), b"drop").expect("writes");

        fixture.sandbox.clear_cache().expect("clears");

        assert!(files.join("keep.txt").exists(), "the data survives");
        assert!(!cache.join("drop.bin").exists(), "the cache is gone");
        assert!(cache.is_dir(), "the directory is recreated so the next resolve works");
        // And a resolve still works afterwards, which is the reason it is recreated.
        assert!(fixture.sandbox.resolve(CACHE, "after.txt").is_ok());
    }

    #[test]
    fn clearing_a_cache_that_is_already_gone_is_not_an_error() {
        // A user may have deleted the whole directory, and a plugin calling clear must not see a failure for
        // something that is already the desired state.
        let fixture = Fixture::new();
        std::fs::remove_dir_all(fixture.sandbox.root().join(CACHE)).expect("removes");
        fixture.sandbox.clear_cache().expect("clears");
        assert!(fixture.sandbox.root().join(CACHE).is_dir());
    }

    #[test]
    fn removing_the_sandbox_takes_everything() {
        let fixture = Fixture::new();
        let root = fixture.sandbox.root().to_path_buf();
        std::fs::write(root.join(FILES).join("x.txt"), b"x").expect("writes");

        fixture.sandbox.remove_all().expect("removes");
        assert!(!root.exists());
    }

    #[test]
    fn two_plugins_get_two_sandboxes() {
        let parent = std::env::temp_dir().join(format!("synra-sandbox-two-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&parent);

        let chat = PluginDataRoot::ensure(&parent, "@synra-plugin/chat").expect("creates");
        let notes = PluginDataRoot::ensure(&parent, "@synra-plugin/notes").expect("creates");

        assert_ne!(chat.root(), notes.root());
        assert!(!chat.contains(notes.root()));
        assert!(!notes.contains(chat.root()));
        // And writing in one is invisible from the other.
        std::fs::write(chat.root().join(FILES).join("secret.txt"), b"secret").expect("writes");
        assert!(matches!(
            notes.resolve(FILES, "secret.txt"),
            Ok(path) if !path.exists()
        ));

        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn opening_an_existing_sandbox_does_not_create_anything() {
        let fixture = Fixture::new();
        let reopened =
            PluginDataRoot::open(fixture.sandbox.root(), "@synra-plugin/chat").expect("opens");
        assert_eq!(reopened.root(), fixture.sandbox.root());
        assert_eq!(reopened.plugin_id(), "@synra-plugin/chat");
    }

    #[test]
    fn opening_a_missing_sandbox_is_unresolvable() {
        let missing = std::env::temp_dir().join(format!("synra-nope-{}", unique_suffix()));
        assert!(matches!(
            PluginDataRoot::open(&missing, "@synra-plugin/chat"),
            Err(PathError::Unresolvable { .. })
        ));
    }

    #[test]
    fn a_meta_record_round_trips_through_json() {
        let meta = SandboxMeta {
            plugin_id: "@synra-plugin/chat".to_owned(),
            files_bytes: 100,
            cache_bytes: 20,
            measured_at_ms: 5,
        };
        let json = serde_json::to_string(&meta).expect("serialises");
        assert!(json.contains("filesBytes"), "{json}");
        let back: SandboxMeta = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, meta);
    }

    #[test]
    fn a_total_that_would_overflow_saturates() {
        // Two counts near the limit is not a realistic plugin, but an overflow would report a small number for a
        // large one — which is the direction that hides a problem.
        let meta = SandboxMeta {
            plugin_id: "x".to_owned(),
            files_bytes: u64::MAX,
            cache_bytes: 1,
            measured_at_ms: 0,
        };
        assert_eq!(meta.total_bytes(), u64::MAX);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// A path a plugin might supply, including the shapes that are meant to escape.
    fn arbitrary_plugin_path() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]{1,8}",
            "[a-z]{1,8}/[a-z]{1,8}",
            "\\.\\./[a-z]{1,8}",
            "\\.\\./\\.\\./[a-z]{1,8}",
            "/[a-z]{1,8}",
            "/etc/[a-z]{1,8}",
            "[a-z]{1,8}/\\.\\./[a-z]{1,8}",
            "\\./[a-z]{1,8}",
            "[a-z]{1,8}//[a-z]{1,8}",
        ]
    }

    proptest! {
        /// Whatever a plugin supplies, a successful resolution is inside the sandbox. This is the property the
        /// whole module exists for: a resolved path a caller then opens must not be able to name the user's
        /// files.
        #[test]
        fn a_resolved_path_is_always_inside(path in arbitrary_plugin_path()) {
            let parent = std::env::temp_dir().join(format!("synra-sandbox-prop-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&parent);
            let sandbox = match PluginDataRoot::ensure(&parent, "@synra-plugin/prop") {
                Ok(sandbox) => sandbox,
                Err(_) => return Ok(()),
            };

            if let Ok(resolved) = sandbox.resolve(FILES, &path) {
                prop_assert!(
                    sandbox.contains(&resolved),
                    "{:?} resolved outside the sandbox to {}",
                    path,
                    resolved.display(),
                );
            }

            let _ = std::fs::remove_dir_all(&parent);
        }

        /// A subdirectory name that is not one of the two is always refused, whatever it looks like. The list is
        /// closed so a plugin cannot name a directory it was never promised.
        #[test]
        fn only_the_documented_subdirectories_resolve(name in ".{0,20}") {
            let parent = std::env::temp_dir().join(format!("synra-sandbox-sub-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&parent);
            let sandbox = match PluginDataRoot::ensure(&parent, "@synra-plugin/prop") {
                Ok(sandbox) => sandbox,
                Err(_) => return Ok(()),
            };

            let allowed = SUBDIRECTORIES.contains(&name.as_str());
            prop_assert_eq!(sandbox.subdirectory(&name).is_ok(), allowed);

            let _ = std::fs::remove_dir_all(&parent);
        }
    }
}
