//! Packument cache entries, TTL and filename-safe storage.

use std::path::{Path, PathBuf};

use super::DEFAULT_TTL_MS;

/// Why a cache operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CacheError {
    /// The cache could not be read or written.
    #[error("the cache entry for `{name}` could not be used: {detail}")]
    Io {
        /// Which plugin.
        name: String,
        /// What the filesystem said.
        detail: String,
    },
    /// The entry exists and is not readable as one.
    ///
    /// ★ Reported rather than treated as a miss, for the reason in the module documentation: a swallowed corruption is an
    /// empty catalogue with no explanation.
    #[error("the cache entry for `{name}` is not readable: {detail}")]
    Corrupt {
        /// Which plugin.
        name: String,
        /// What the parser said.
        detail: String,
    },
}

/// A cache entry, and how old it is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cached {
    /// Within its lifetime.
    Fresh {
        /// The packument, as it was fetched.
        text: String,
        /// How long ago it was fetched.
        age_ms: i64,
    },
    /// Past its lifetime, and still returned.
    ///
    /// # Why this is a variant rather than a rejection
    ///
    /// Because the design's answer to an unreachable registry is to use the cached document and say so. A type that refused
    /// to hand one back would leave the caller with nothing to show, and the caller is the only thing that knows whether
    /// "eight days old" is acceptable for what it is doing.
    Stale {
        /// The packument, as it was fetched.
        text: String,
        /// How long ago it was fetched.
        age_ms: i64,
    },
}

impl Cached {
    /// The document, whichever kind of entry this is.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Fresh { text, .. } | Self::Stale { text, .. } => text,
        }
    }

    /// How long ago it was fetched.
    #[must_use]
    pub const fn age_ms(&self) -> i64 {
        match self {
            Self::Fresh { age_ms, .. } | Self::Stale { age_ms, .. } => *age_ms,
        }
    }

    /// Whether it is past its lifetime.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

/// One cache entry on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    /// The plugin name this is for, so a file whose name was computed from something else is detectable.
    name: String,
    /// When it was fetched.
    fetched_at_ms: i64,
    /// The document.
    text: String,
}

/// A directory of cached packuments.
#[derive(Debug, Clone)]
pub struct CatalogCache {
    dir: PathBuf,
    ttl_ms: i64,
}

impl CatalogCache {
    /// A cache in this directory, with the design's lifetime.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into(), ttl_ms: DEFAULT_TTL_MS }
    }

    /// The same cache with a different lifetime.
    #[must_use]
    pub const fn with_ttl(mut self, ttl_ms: i64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// Where it keeps its entries.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Records a packument, stamping it with the moment it was fetched.
    ///
    /// # Errors
    ///
    /// [`CacheError::Io`] when the directory or the file cannot be written. A caller may treat that as a warning: failing to
    /// cache a document that was just fetched is not a reason to fail the fetch.
    pub fn store(&self, name: &str, text: &str, now_ms: i64) -> Result<(), CacheError> {
        let path = self.path_for(name)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| CacheError::Io {
                name: name.to_owned(),
                detail: error.to_string(),
            })?;
        }
        let entry = Entry {
            name: name.to_owned(),
            fetched_at_ms: now_ms,
            text: text.to_owned(),
        };
        let encoded = serde_json::to_string(&entry).map_err(|error| CacheError::Io {
            name: name.to_owned(),
            detail: error.to_string(),
        })?;
        std::fs::write(&path, encoded).map_err(|error| CacheError::Io {
            name: name.to_owned(),
            detail: error.to_string(),
        })
    }

    /// Reads a packument, saying how old it is.
    ///
    /// `Ok(None)` means there is no entry; a corrupt one is [`CacheError::Corrupt`].
    ///
    /// # Errors
    ///
    /// [`CacheError`] for a cache that cannot be read and for an entry that is not one.
    pub fn load(&self, name: &str, now_ms: i64) -> Result<Option<Cached>, CacheError> {
        let path = self.path_for(name)?;
        let encoded = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(CacheError::Io { name: name.to_owned(), detail: error.to_string() });
            }
        };
        let entry: Entry = serde_json::from_str(&encoded).map_err(|error| CacheError::Corrupt {
            name: name.to_owned(),
            detail: error.to_string(),
        })?;

        // ★ The name is checked against the entry's own copy of it.
        //
        // Not for security — the path was computed from the name, so a mismatch cannot point somewhere else — but because a
        // mismatch means the encoder's name mapping is not reversible, which would make two plugins share one cache entry.
        if entry.name != name {
            return Err(CacheError::Corrupt {
                name: name.to_owned(),
                detail: format!("the entry is for `{}`", entry.name),
            });
        }

        // A clock that went backwards, or an entry written by a machine whose clock is ahead, gives a negative age. Clamped
        // rather than reported: the age is for a message, and a negative one in a message is worse than a zero.
        let age_ms = now_ms.saturating_sub(entry.fetched_at_ms).max(0);
        Ok(Some(if age_ms <= self.ttl_ms {
            Cached::Fresh { text: entry.text, age_ms }
        } else {
            Cached::Stale { text: entry.text, age_ms }
        }))
    }

    /// Removes an entry, and says whether there was one.
    ///
    /// # Errors
    ///
    /// [`CacheError::Io`] when the file exists and cannot be removed.
    pub fn forget(&self, name: &str) -> Result<bool, CacheError> {
        let path = self.path_for(name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(CacheError::Io { name: name.to_owned(), detail: error.to_string() }),
        }
    }

    /// The file one name maps to.
    ///
    /// ★ **A name is a key, never a path.** `@acme/chat` is one flat file name here, and so is `../../etc/passwd` — which is
    /// the point: the escaping is over the **bytes** of the name, so no name at all can produce a separator, a `..`, or a
    /// drive prefix. A mapping that replaced only `/` would still let a Windows-style `..\..\x` through on a machine that
    /// treats backslashes as separators.
    fn path_for(&self, name: &str) -> Result<PathBuf, CacheError> {
        if name.is_empty() {
            return Err(CacheError::Io {
                name: name.to_owned(),
                detail: "a plugin name cannot be empty".to_owned(),
            });
        }
        let file = format!("{FILE_PREFIX}{}.json", escape(name));
        // ★ The length is checked rather than left to the filesystem.
        //
        // Escaping triples the worst case, so a long plugin name produces a file name no filesystem accepts — and the
        // failure a caller sees would be an `Io` error from an operation it did not know was about length. Refused here, with
        // the two numbers, because a plugin name that cannot be cached is a fact about the name.
        if file.len() > MAX_FILE_NAME_BYTES {
            return Err(CacheError::Io {
                name: name.to_owned(),
                detail: format!(
                    "its cache file name would be {} bytes, and the limit is {MAX_FILE_NAME_BYTES}",
                    file.len()
                ),
            });
        }
        Ok(self.dir.join(file))
    }
}

/// The longest file name a cache entry may have.
///
/// Conservative on purpose: the common limits are 255 **bytes**, and this leaves room for nothing else because nothing else
/// is added — the directory is not part of a name.
const MAX_FILE_NAME_BYTES: usize = 255;

/// What every cache file name starts with.
///
/// ★ **Not decoration.** A plugin name is usually made of letters, digits, `@`, `/` and `.` — and an all-alphanumeric name is
/// escaped **to itself**, so a plugin called `CON`, `NUL`, `PRN`, `AUX`, `COM1` or `LPT1` produced a file called `CON.json`.
/// On Windows that is not a file: the name is resolved to a **device** before the filesystem is consulted, so the write went
/// to the console and the cache stayed empty — which is what the escaping test caught, on the one platform where it matters.
///
/// A prefix that is not one of those names means no plugin name can ever produce one. It also keeps a cache file from being
/// mistaken for a plugin directory's own contents, which is a smaller reason for the same choice.
const FILE_PREFIX: &str = "packument-";

/// A plugin name as a single filename component.
///
/// Every byte that is not an ASCII letter or digit becomes `_` followed by two hex digits, so the mapping is reversible in
/// principle and — the part that matters — **injective over the characters that could otherwise merge two names**. `_` is
/// itself escaped, so `a_b` and `a` + a separator cannot collide.
fn escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len() * 3);
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() {
            out.push(char::from(byte));
        } else {
            out.push('_');
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}


