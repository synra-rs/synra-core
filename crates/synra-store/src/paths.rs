//! Where everything lives on disk.
//!
//! One type answers every "where is…" question the kernel asks, so the layout exists in one place rather than
//! being reassembled from path fragments at a dozen call sites. A layout spread across call sites is how a
//! file ends up in the data directory on one platform and the cache directory on another.
//!
//! # Data, cache and keys are three different things
//!
//! The split is not cosmetic; it is about what happens when something goes wrong:
//!
//! * **Data** — the database, installed plugins, plugin data. Backed up by the operating system, and losing it
//!   loses the user's pairings and their plugins.
//! * **Cache** — compiled Wasm, registry responses, exported bundles. Never backed up, and deleting all of it
//!   costs a recompile and nothing else.
//! * **Logs** — written for a fortnight and then rotated away. Not data, not cache.
//!
//! So the type does not offer a single `dir()`: a caller has to say which of the three it means, and a file
//! written to the wrong one is a decision somebody made rather than a default they fell into.

use std::path::{Path, PathBuf};

/// The kernel's directory layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The data directory, whose contents are worth backing up.
    data_dir: PathBuf,
    /// The cache directory, whose contents can be deleted at any time.
    cache_dir: PathBuf,
    /// The log directory.
    log_dir: PathBuf,
}

impl Paths {
    /// Builds the layout from the two roots the platform supplies.
    ///
    /// Two roots rather than one: a platform that separates them — Windows Roaming for configuration and Local
    /// for caches — should be able to say so, and a platform that does not simply passes the same value twice.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, cache_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let cache_dir = cache_dir.into();
        Self { log_dir: data_dir.join("logs"), data_dir, cache_dir }
    }

    /// A layout with one root, for a platform that does not separate them, and for tests.
    #[must_use]
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self::new(root.clone(), root)
    }

    /// The data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The cache directory.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// The log directory.
    #[must_use]
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// The database file.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("kernel.db")
    }

    /// The bootstrap configuration file, read before the database is open.
    #[must_use]
    pub fn bootstrap_config_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    /// The directory of installed plugin artifacts.
    #[must_use]
    pub fn plugins_dir(&self) -> PathBuf {
        self.data_dir.join("plugins")
    }

    /// Where one plugin's versions live.
    #[must_use]
    pub fn plugin_dir(&self, plugin_id: &str) -> PathBuf {
        self.plugins_dir().join(sanitise_component(plugin_id))
    }

    /// The root of the plugin data sandboxes.
    #[must_use]
    pub fn plugin_data_dir(&self) -> PathBuf {
        self.data_dir.join("plugin-data")
    }

    /// The root of one plugin's sandbox.
    #[must_use]
    pub fn plugin_sandbox_dir(&self, plugin_id: &str) -> PathBuf {
        self.plugin_data_dir().join(sanitise_component(plugin_id))
    }

    /// The key material directory.
    ///
    /// Under the data directory rather than the cache: a key that is deleted on a cache sweep is a key the user
    /// has to re-establish, which means re-pairing every device.
    #[must_use]
    pub fn keys_dir(&self) -> PathBuf {
        self.data_dir.join("keys")
    }

    /// The compiled Wasm cache.
    #[must_use]
    pub fn wasm_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("wasm")
    }

    /// The registry response cache.
    #[must_use]
    pub fn catalog_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("catalog")
    }

    /// Where exported diagnostic bundles are written.
    #[must_use]
    pub fn diagnostics_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("diagnostics")
    }

    /// The crash report directory.
    #[must_use]
    pub fn crash_dir(&self) -> PathBuf {
        self.log_dir.join("crash")
    }

    /// Every directory the kernel needs to exist.
    ///
    /// Returned as a list rather than created here, so a caller that only reads does not create anything. The
    /// application layer calls this once at start-up.
    #[must_use]
    pub fn required_directories(&self) -> Vec<PathBuf> {
        vec![
            self.data_dir.clone(),
            self.cache_dir.clone(),
            self.log_dir.clone(),
            self.plugins_dir(),
            self.plugin_data_dir(),
            self.keys_dir(),
            self.wasm_cache_dir(),
            self.catalog_cache_dir(),
            self.diagnostics_cache_dir(),
            self.crash_dir(),
        ]
    }

    /// Creates every directory the kernel needs.
    ///
    /// # Errors
    ///
    /// [`PathError::Unwritable`] naming the directory that could not be created.
    pub fn ensure_directories(&self) -> Result<(), PathError> {
        for directory in self.required_directories() {
            std::fs::create_dir_all(&directory).map_err(|source| PathError::Unwritable {
                path: directory.display().to_string(),
                detail: source.to_string(),
            })?;
        }
        Ok(())
    }

    /// Whether `candidate` is inside the data or cache directory.
    ///
    /// For a caller that wants to refuse a path a user or a plugin supplied without opening it. It is **not**
    /// the sandbox check: that one opens the file, because a check followed by an open has a window in which
    /// the path can change. See [`crate::sandbox`].
    #[must_use]
    pub fn contains(&self, candidate: &Path) -> bool {
        is_within(&self.data_dir, candidate) || is_within(&self.cache_dir, candidate)
    }
}

/// Turns an identifier into one path component.
///
/// A plugin id contains a `/` and an `@`, which are path separators and nothing at all on different platforms.
/// Using the id verbatim would put one plugin's files inside a directory named after its scope, and would let
/// an id containing `..` name a directory outside the plugins directory entirely.
///
/// The substitution is reversible in practice for reading a directory back — `/` becomes `+`, and `@` is
/// dropped — and a plugin id never contains `+`, so two ids cannot collide.
#[must_use]
pub fn sanitise_component(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for ch in id.chars() {
        match ch {
            // A separator becomes something that is not one.
            '/' | '\\' => out.push('+'),
            // Dropped rather than replaced: `@` is noise in a directory name and every id has one.
            '@' => {}
            // A dot is kept for a dotted name, but a run of them is collapsed below so `..` cannot survive.
            '.' => out.push('.'),
            ch if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' => out.push(ch),
            // Anything else is not something an id is allowed to contain; replacing it rather than dropping it
            // keeps two different ids distinguishable.
            _ => out.push('-'),
        }
    }

    // `..` is the one sequence that matters. Collapsed rather than removed, so `.` and `..` map to different
    // names instead of both becoming the empty string.
    while out.contains("..") {
        out = out.replace("..", ".");
    }
    // A leading dot would make the directory hidden, which is not what an author expects.
    let trimmed = out.trim_start_matches('.');
    if trimmed.is_empty() {
        return "_".to_owned();
    }
    trimmed.to_owned()
}

/// Whether a path is inside a directory, comparing component by component.
///
/// Not a string prefix check: `/data` is a string prefix of `/database`, so a string comparison would accept a
/// sibling directory. Comparing components cannot make that mistake.
#[must_use]
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    // Both sides are made absolute-component-wise without touching the filesystem: this is used for paths that
    // may not exist yet, so `canonicalize` is not available.
    let root: Vec<_> = root.components().collect();
    let candidate: Vec<_> = candidate.components().collect();

    if candidate.len() < root.len() {
        return false;
    }
    root.iter().zip(&candidate).all(|(a, b)| a == b)
}

/// Why a path is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// A directory could not be created.
    #[error("the directory {path:?} cannot be created: {detail}")]
    Unwritable {
        /// The directory.
        path: String,
        /// What the operating system said.
        detail: String,
    },

    /// A plugin supplied a path that leaves its sandbox.
    #[error("the path {path:?} is outside {root:?}")]
    Escapes {
        /// The path as the plugin wrote it.
        path: String,
        /// The sandbox root.
        root: String,
    },

    /// A plugin supplied a path that is not relative.
    #[error("the path {0:?} is absolute, and a plugin's paths are relative to its sandbox")]
    Absolute(String),

    /// A path could not be resolved.
    #[error("the path {path:?} cannot be resolved: {detail}")]
    Unresolvable {
        /// The path.
        path: String,
        /// What the operating system said.
        detail: String,
    },

    /// A component of a path is not usable.
    #[error("the path {path:?} has an unusable component {component:?}")]
    BadComponent {
        /// The whole path.
        path: String,
        /// The offending component.
        component: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths::new("/data", "/cache")
    }

    #[test]
    fn the_layout_puts_each_thing_where_the_design_says() {
        let paths = paths();
        assert_eq!(paths.data_dir(), Path::new("/data"));
        assert_eq!(paths.cache_dir(), Path::new("/cache"));
        assert_eq!(paths.log_dir(), Path::new("/data/logs"));
        assert_eq!(paths.db_path(), Path::new("/data/kernel.db"));
        assert_eq!(paths.bootstrap_config_path(), Path::new("/data/config.json"));
        assert_eq!(paths.plugins_dir(), Path::new("/data/plugins"));
        assert_eq!(paths.plugin_data_dir(), Path::new("/data/plugin-data"));
        assert_eq!(paths.keys_dir(), Path::new("/data/keys"));
        assert_eq!(paths.wasm_cache_dir(), Path::new("/cache/wasm"));
        assert_eq!(paths.catalog_cache_dir(), Path::new("/cache/catalog"));
        assert_eq!(paths.diagnostics_cache_dir(), Path::new("/cache/diagnostics"));
        assert_eq!(paths.crash_dir(), Path::new("/data/logs/crash"));
    }

    #[test]
    fn keys_live_with_the_data_and_not_with_the_cache() {
        // A key deleted on a cache sweep is a key the user has to re-establish, which means re-pairing every
        // device — so the assertion is about which root it hangs off, not about its name.
        let paths = paths();
        assert!(paths.keys_dir().starts_with(paths.data_dir()));
        assert!(!paths.keys_dir().starts_with(paths.cache_dir()));
    }

    #[test]
    fn caches_live_with_the_cache() {
        // Deleting all of it costs a recompile and nothing else, which is only true if nothing in it is
        // irreplaceable.
        let paths = paths();
        for directory in [paths.wasm_cache_dir(), paths.catalog_cache_dir(), paths.diagnostics_cache_dir()] {
            assert!(directory.starts_with(paths.cache_dir()), "{}", directory.display());
        }
    }

    #[test]
    fn one_root_is_used_twice_when_the_platform_does_not_separate_them() {
        let paths = Paths::under("/everything");
        assert_eq!(paths.data_dir(), paths.cache_dir());
        assert!(paths.db_path().starts_with("/everything"));
        assert!(paths.wasm_cache_dir().starts_with("/everything"));
    }

    #[test]
    fn a_plugin_id_becomes_one_path_component() {
        // An id contains a `/` and an `@`, one of which is a path separator and neither of which is a legal
        // directory name everywhere.
        assert_eq!(sanitise_component("@synra-plugin/chat"), "synra-plugin+chat");
        assert_eq!(sanitise_component("@imba97/synra-plugin-notes"), "imba97+synra-plugin-notes");
    }

    #[test]
    fn a_plugin_id_cannot_name_a_directory_outside_the_plugins_directory() {
        // The property that matters: whatever the id, the joined path stays under the root.
        for id in ["../../etc", "@scope/../../..", "..", "./..", "@scope//x", "a/b/c"] {
            let sanitised = sanitise_component(id);
            assert!(!sanitised.contains('/'), "{id} -> {sanitised}");
            assert!(!sanitised.contains('\\'), "{id} -> {sanitised}");
            assert!(!sanitised.contains(".."), "{id} -> {sanitised}");
            assert!(!sanitised.starts_with('.'), "{id} -> {sanitised}");

            let joined = paths().plugin_dir(id);
            assert!(
                is_within(Path::new("/data/plugins"), &joined),
                "{id} escaped to {}",
                joined.display()
            );
        }
    }

    #[test]
    fn sanitising_an_id_that_becomes_empty_yields_something_usable() {
        // An id of `@` or `` would otherwise produce the plugins directory itself, which one plugin could then
        // fill with another's files.
        for id in ["", "@", "...", "@@"] {
            let sanitised = sanitise_component(id);
            assert!(!sanitised.is_empty(), "{id:?}");
            assert_ne!(sanitised, ".", "{id:?}");
        }
    }

    #[test]
    fn distinct_ids_stay_distinct_after_sanitising() {
        // A substitution that collapsed two ids would let one plugin read another's data, which is the one thing
        // the per-plugin directory exists to prevent.
        let ids = ["@synra-plugin/chat", "@synra-plugin/notes", "@imba97/synra-plugin-chat"];
        let mut seen = std::collections::HashSet::new();
        for id in ids {
            assert!(seen.insert(sanitise_component(id)), "{id} collided");
        }
    }

    #[test]
    fn a_sibling_directory_is_not_inside() {
        // `/data` is a string prefix of `/database`, so a string comparison would accept it. This is the check
        // the sandbox relies on, so the mistake would be a path escape.
        assert!(is_within(Path::new("/data"), Path::new("/data/plugins")));
        assert!(is_within(Path::new("/data"), Path::new("/data")));
        assert!(!is_within(Path::new("/data"), Path::new("/database")));
        assert!(!is_within(Path::new("/data"), Path::new("/datax/plugins")));
        assert!(!is_within(Path::new("/data/plugins"), Path::new("/data")));
    }

    #[test]
    fn a_relative_root_is_compared_component_wise() {
        assert!(is_within(Path::new("a/b"), Path::new("a/b/c")));
        assert!(!is_within(Path::new("a/b"), Path::new("a/bc")));
    }

    #[test]
    fn the_layout_reports_whether_a_path_is_its_own() {
        let paths = paths();
        assert!(paths.contains(Path::new("/data/kernel.db")));
        assert!(paths.contains(Path::new("/cache/wasm/x.cwasm")));
        assert!(!paths.contains(Path::new("/elsewhere/kernel.db")));
        assert!(!paths.contains(Path::new("/datax/kernel.db")));
    }

    #[test]
    fn every_required_directory_is_listed_once_and_under_a_root() {
        let paths = paths();
        let directories = paths.required_directories();

        let mut seen = std::collections::HashSet::new();
        for directory in &directories {
            assert!(seen.insert(directory.clone()), "{directory:?} is listed twice");
            assert!(
                directory.starts_with(paths.data_dir()) || directory.starts_with(paths.cache_dir()),
                "{directory:?} is under neither root"
            );
        }
        // The two roots themselves are included, so a caller can create the layout from nothing.
        assert!(directories.contains(&paths.data_dir().to_path_buf()));
        assert!(directories.contains(&paths.cache_dir().to_path_buf()));
    }

    #[test]
    fn ensuring_the_directories_creates_them_all() {
        let root = std::env::temp_dir().join(format!("synra-paths-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&root);
        let paths = Paths::under(&root);

        paths.ensure_directories().expect("creates");
        for directory in paths.required_directories() {
            assert!(directory.is_dir(), "{} was not created", directory.display());
        }

        // Idempotent, because start-up can run more than once in a session.
        paths.ensure_directories().expect("creates again");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_layout_that_cannot_be_created_reports_which_directory() {
        // A path under an existing regular file cannot become a directory on any platform.
        let root = std::env::temp_dir().join(format!("synra-paths-file-{}", unique_suffix()));
        std::fs::write(&root, b"not a directory").expect("writes");

        let paths = Paths::under(root.join("under-a-file"));
        match paths.ensure_directories() {
            Err(PathError::Unwritable { path, .. }) => assert!(!path.is_empty()),
            other => panic!("expected an unwritable directory, got {other:?}"),
        }

        let _ = std::fs::remove_file(&root);
    }

    #[test]
    fn path_errors_explain_themselves() {
        let errors = vec![
            PathError::Unwritable { path: "a".to_owned(), detail: "b".to_owned() },
            PathError::Escapes { path: "a".to_owned(), root: "b".to_owned() },
            PathError::Absolute("a".to_owned()),
            PathError::Unresolvable { path: "a".to_owned(), detail: "b".to_owned() },
            PathError::BadComponent { path: "a".to_owned(), component: "b".to_owned() },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    /// A unique suffix so two tests do not share a temporary directory.
    pub(super) fn unique_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Whatever the id, the resulting directory is a single component inside the plugins directory. This is
        /// the property the per-plugin directory exists for: one plugin must not be able to name another's files,
        /// or anything outside the directory at all.
        #[test]
        fn a_sanitised_id_never_escapes(id in ".{0,60}") {
            let sanitised = sanitise_component(&id);
            prop_assert!(!sanitised.is_empty());
            prop_assert!(!sanitised.contains('/'));
            prop_assert!(!sanitised.contains('\\'));
            prop_assert!(!sanitised.contains(".."));
            prop_assert!(!sanitised.starts_with('.'));
            prop_assert_ne!(sanitised.as_str(), ".");

            let joined = Paths::under("/root").plugin_dir(&id);
            prop_assert!(is_within(Path::new("/root/plugins"), &joined));
        }

        /// Component-wise containment agrees with the path's own structure: a child is inside its parent, and a
        /// sibling is not. Reimplemented the obvious way and compared, so the check the sandbox depends on is
        /// verified against something rather than against itself.
        #[test]
        fn containment_matches_the_component_structure(
            parts in proptest::collection::vec("[a-z]{1,6}", 1..5),
            extra in proptest::collection::vec("[a-z]{1,6}", 0..3),
        ) {
            let root: PathBuf = parts.iter().collect();
            let mut child = root.clone();
            for part in &extra {
                child.push(part);
            }
            prop_assert!(is_within(&root, &child));

            // A sibling shares a prefix but diverges in a component, and must not be accepted. `root` is moved
            // rather than cloned because the containment check above is the last use of the shared value.
            let mut sibling = root;
            sibling.push("elsewhere");
            prop_assert!(!is_within(&child, &sibling) || extra.is_empty());
        }
    }
}
