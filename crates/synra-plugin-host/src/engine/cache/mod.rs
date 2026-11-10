//! Where a compiled plugin is kept between runs, and why the key has four parts.
//!
//! # The failure this module exists to prevent
//!
//! A precompiled artefact is **machine code for one engine**. Loading one produced by a different build of `wasmtime`
//! is not a slow path — it is an undefined one: the bytes decode as instructions, and what they do is whatever they
//! happen to mean. So the cache key names every input that changes the bytes:
//!
//! | Part | Why it is in the key |
//! | --- | --- |
//! | the artefact digest | a different plugin is a different program |
//! | the backend kind | a JIT's output and an interpreter's are not the same file |
//! | the engine version | an engine upgrade changes the encoding |
//! | the target triple | the same engine on another architecture emits other instructions |
//!
//! A cache that keyed on the digest alone would work perfectly in development, on one machine, for one release — and
//! would be a crash the first time a user upgraded.
//!
//! # Why the index is a file and not a table
//!
//! Because the cache is a *cache*: every entry can be recomputed from the artefact, so losing the index costs a
//! recompilation and nothing else. Putting it in SQLite would make the kernel's schema carry a table whose contents it
//! does not promise, and a migration for a thing that is allowed to disappear.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::types::BackendKind;

/// The extension a precompiled artefact is written with.
///
/// A name of its own rather than `.wasm`, so a directory listing does not suggest the file is a component — loading one
/// as a component is exactly the mistake the key exists to prevent.
pub const CACHED_EXTENSION: &str = "cwasm";

/// Why a cache operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// The directory could not be created or read.
    #[error("the compile cache could not be used: {detail}")]
    Io {
        /// What the filesystem said.
        detail: String,
    },

    /// A key named a file that is not a valid file name.
    ///
    /// Refused rather than sanitised: a key is built from a digest, a backend name, a version and a target triple, and
    /// a key with a path separator in it means one of those came from somewhere it should not have.
    #[error("{key} is not usable as a cache key")]
    BadKey {
        /// The key.
        key: String,
    },
}

/// What produced a compiled artefact.
///
/// Every field is an input to the bytes, which is the property the type exists to make visible: a field added here is a
/// cache that stops being wrong when the new input changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The digest of the `.wasm` the artefact was compiled from.
    pub artifact_digest: String,
    /// Which engine compiled it.
    pub backend: BackendKind,
    /// The engine's version.
    pub engine_version: String,
    /// The target the artefact was compiled for.
    pub target: String,
}

impl CacheKey {
    /// Builds a key.
    #[must_use]
    pub fn new(
        artifact_digest: impl Into<String>,
        backend: BackendKind,
        engine_version: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            artifact_digest: artifact_digest.into(),
            backend,
            engine_version: engine_version.into(),
            target: target.into(),
        }
    }

    /// The file name this key maps to.
    ///
    /// # Why the parts are joined with `-` and not with a path separator
    ///
    /// Because the whole point is that the name is flat. A directory per part would make an upgrade leave a tree of
    /// directories nothing ever reads again, and a sweep of this cache is a listing of one directory.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!(
            "{}-{}-{}-{}.{CACHED_EXTENSION}",
            self.artifact_digest, self.backend, self.engine_version, self.target
        )
    }

    /// Whether this key can be a file name.
    ///
    /// The separator check is the one that matters: a key containing `/` or `\` would escape the cache directory, and
    /// the digest is the field a caller is most likely to have taken from somewhere untrusted. The length check is what
    /// refuses an empty digest — `all` over an empty iterator is true, so the shape check alone would accept one.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        let name = self.file_name();
        !name.is_empty()
            && !name.contains(['/', '\\', '\0'])
            && !name.contains("..")
            && !self.artifact_digest.is_empty()
            && self.artifact_digest.chars().all(|character| character.is_ascii_hexdigit())
    }

    /// The key in one line, for a log.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} on {}/{} for {}",
            self.artifact_digest, self.backend, self.engine_version, self.target
        )
    }
}

/// One cache entry, as the index records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    /// The key it is filed under.
    pub key: String,
    /// The digest of the compiled bytes, so a truncated write is noticed rather than loaded.
    pub compiled_digest: String,
    /// How many bytes it holds.
    pub bytes: u64,
    /// When it was written, in signed milliseconds since the epoch.
    pub written_at_ms: i64,
    /// How many times it has been handed out.
    pub hits: u64,
}

/// A directory of precompiled artefacts.
///
/// # Why this holds no lock of its own
///
/// Because it is a directory: two processes writing the same key write the same bytes, and the write is done to a
/// temporary name and renamed, which is atomic on every filesystem the kernel targets. A lock would serialise the case
/// that cannot go wrong.
#[derive(Debug, Clone)]
pub struct CompileCache {
    root: PathBuf,
    target: String,
}

impl CompileCache {
    /// Opens a cache under a directory, creating it if it is absent.
    ///
    /// The `root` is the caller's — `<data-dir>/cache/wasm` in a running kernel — because a cache that decided its own
    /// location would be a cache inside a source tree.
    ///
    /// # Errors
    ///
    /// [`CacheError::Io`] when the directory cannot be created.
    pub fn open(root: impl AsRef<Path>, target: impl Into<String>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|error| CacheError::Io { detail: error.to_string() })?;
        Ok(Self { root, target: target.into() })
    }

    /// Where the cache lives.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The target its artefacts are compiled for.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The key for an artefact and a backend.
    #[must_use]
    pub fn key(
        &self,
        artifact_digest: impl Into<String>,
        backend: BackendKind,
        engine_version: impl Into<String>,
    ) -> CacheKey {
        CacheKey::new(artifact_digest, backend, engine_version, self.target.clone())
    }

    /// The bytes filed under a key, when there are any.
    ///
    /// # Errors
    ///
    /// [`CacheError::BadKey`] for a key that is not a file name, or [`CacheError::Io`] when the file exists and cannot
    /// be read. A *missing* file is `Ok(None)`, which is the ordinary case: the cache is allowed to be cold.
    pub fn load(&self, key: &CacheKey) -> Result<Option<Vec<u8>>, CacheError> {
        if !key.is_safe() {
            return Err(CacheError::BadKey { key: key.file_name() });
        }
        match fs::read(self.path_of(key)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(CacheError::Io { detail: error.to_string() }),
        }
    }

    /// Files bytes under a key.
    ///
    /// # Errors
    ///
    /// [`CacheError::BadKey`] for a key that is not a file name, or [`CacheError::Io`] when the write fails.
    pub fn store(&self, key: &CacheKey, bytes: &[u8], now_ms: i64) -> Result<(), CacheError> {
        if !key.is_safe() {
            return Err(CacheError::BadKey { key: key.file_name() });
        }
        // ★ Written to a temporary name and renamed. A process killed mid-write would otherwise leave a file that
        // decodes as a truncated artefact, which loads as garbage rather than as a miss — and the next start would load
        // it again, because a cache entry is not revalidated.
        let path = self.path_of(key);
        let temporary = path.with_extension(format!("{CACHED_EXTENSION}.part"));
        fs::write(&temporary, bytes).map_err(|error| CacheError::Io { detail: error.to_string() })?;
        fs::rename(&temporary, &path).map_err(|error| CacheError::Io { detail: error.to_string() })?;
        let _ = now_ms;
        Ok(())
    }

    /// Removes everything, which a `--no-cache` start does.
    ///
    /// # Errors
    ///
    /// [`CacheError::Io`] when a file cannot be removed. Files that fail are left where they are: one unreadable entry
    /// is not a reason to refuse the ones that were removed.
    pub fn clear(&self) -> Result<usize, CacheError> {
        let mut removed = 0_usize;
        let entries = fs::read_dir(&self.root).map_err(|error| CacheError::Io { detail: error.to_string() })?;
        for entry in entries.flatten() {
            let path = entry.path();
            let is_ours = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension == CACHED_EXTENSION || extension == "part");
            if is_ours && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Everything in the cache, for a `doctor` report.
    ///
    /// # Errors
    ///
    /// [`CacheError::Io`] when the directory cannot be read.
    pub fn entries(&self) -> Result<Vec<(String, u64)>, CacheError> {
        let mut found = Vec::new();
        let entries = fs::read_dir(&self.root).map_err(|error| CacheError::Io { detail: error.to_string() })?;
        for entry in entries.flatten() {
            let path = entry.path();
            let cached = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension == CACHED_EXTENSION);
            if !cached {
                continue;
            }
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_owned();
            let bytes = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            found.push((name, bytes));
        }
        found.sort();
        Ok(found)
    }

    /// The full path of a key's file.
    #[must_use]
    pub fn path_of(&self, key: &CacheKey) -> PathBuf {
        self.root.join(key.file_name())
    }
}

#[cfg(test)]
mod tests;
