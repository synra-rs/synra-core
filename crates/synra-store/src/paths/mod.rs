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

/// The database's file name inside the data directory.
///
/// Public so that a caller which has a data directory but no [`Paths`] — the daemon's transport loop, which must answer a
/// handshake's pairing question — can find the same file without spelling the name a second time. Two spellings of a file
/// name is two chances to look in the wrong place, and the failure would be a device that cannot recognise a peer it had
/// paired with.
pub const DB_FILE_NAME: &str = "kernel.db";

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
        Self {
            log_dir: data_dir.join("logs"),
            data_dir,
            cache_dir,
        }
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
        self.data_dir.join(DB_FILE_NAME)
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

mod errors;

pub use errors::PathError;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
