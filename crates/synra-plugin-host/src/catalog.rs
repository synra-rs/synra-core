//! The catalogue: a packument cache with a lifetime, and the client that fills it.
//!
//! # Why this exists
//!
//! Because `catalog_cache_dir()` was a path with nothing behind it, `Packument::parse` had no production caller, and the
//! design's first offline row — *"registry unreachable → use the cached packument (7-day TTL); show offline mode"* — had no
//! cache, no lifetime, and no fallback. `RegistryConfig::resolve` could say *where* to look and nothing could look.
//!
//! # The three things that are easy to get wrong, and what this does instead
//!
//! 1. **A plugin name is not a filename.** Names are `@scope/name`, and joining one onto a directory both creates a
//!    subdirectory and makes `../../etc/x` a path out of the cache. [`CatalogCache`] escapes the name into a single flat
//!    component, so a name is a **key** and never a path.
//! 2. **A cache's lifetime is about when it was fetched, not when the file was written.** A file's timestamp can be set to
//!    anything by anything, and a cache entry whose age is read from the filesystem is a lifetime that a clock change
//!    rewrites. The fetch time is stored **inside** the entry.
//! 3. **Stale is not the same as absent.** The design's row is to *use* the cached document and announce it, not to refuse to
//!    start — so [`Cached::Stale`] carries the document and its age, and the caller is what decides to show "offline mode".
//!    A cache that answered `None` past its lifetime would turn a slow network into an empty catalogue.
//!
//! # What a corrupt entry does
//!
//! It is an **error**, not a miss. A cache is not a source of truth, and the tempting design is to swallow a bad entry and
//! report "nothing cached" — but then a systematic bug in this module (a wrong encoding, a changed field name) presents as an
//! empty catalogue forever, with nothing anywhere saying the entries exist and cannot be read. The caller can still treat it
//! as a miss; what it cannot do is not be told.

use std::path::{Path, PathBuf};

use super::registry::{Packument, RegistryConfig};

/// How long a cached packument may be used as though it were current.
///
/// The design's number, in milliseconds. Past it the document is still returned — see the module documentation on stale
/// entries — but it is marked, because a catalogue from eight days ago is a different thing from one from eight minutes ago
/// and only the caller knows whether the difference matters to what it is about to do.
pub const DEFAULT_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

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

/// What a catalogue client needs from a fetcher.
///
/// # Why a trait rather than `synra_fetch::Client`
///
/// Because the interesting behaviour here is what happens when a fetch **fails** — every mirror unreachable, a mirror that
/// answers with something that is not a packument, a cache that saves the day — and none of that can be tested through a
/// type whose failures require a network. The real client implements this in three lines; the tests implement it with a
/// script.
pub trait Fetches {
    /// Fetches a URL, as bytes.
    ///
    /// # Errors
    ///
    /// A string saying why, which is shown to the user: every reason here is a fact about the network or a registry, and the
    /// design's second offline row is explicit that a failure must be **reported** rather than papered over.
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// Where a packument came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A registry answered.
    Registry {
        /// Which mirror, as the configuration spells it.
        mirror: String,
    },
    /// The cache did.
    Cache {
        /// How old the entry is.
        age_ms: i64,
        /// Whether it is past its lifetime.
        stale: bool,
    },
}

/// A packument and where it came from.
///
/// `PartialEq` and not `Eq`, because [`Packument`] is: its version entries carry floats, and equality over those is the
/// question the type already answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Fetched {
    /// The document.
    pub packument: Packument,
    /// Where it came from, which is what a screen shows "offline mode" from.
    pub origin: Origin,
}

/// Why a packument could not be obtained.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// The configuration has no mirror for this package.
    #[error("no registry is configured for `{package}`")]
    NoRegistry {
        /// Which plugin.
        package: String,
    },
    /// Every mirror refused, and the cache had nothing.
    ///
    /// ★ Each attempt is carried. "the registry is unreachable" is not actionable; "mirror A timed out, mirror B answered
    /// 503, and nothing was cached" is.
    #[error("no mirror answered for `{package}` and nothing was cached: {attempts:?}")]
    Unreachable {
        /// Which plugin.
        package: String,
        /// What each mirror said, in the order they were tried.
        attempts: Vec<(String, String)>,
    },
    /// A mirror answered with something that is not a packument.
    #[error("`{package}` could not be read: {detail}")]
    Unreadable {
        /// Which plugin.
        package: String,
        /// What the parser said.
        detail: String,
    },
    /// The cache could not be used.
    #[error(transparent)]
    Cache(#[from] CacheError),
}

/// The catalogue, over a set of mirrors and a cache.
#[derive(Debug)]
pub struct CatalogClient<F> {
    config: RegistryConfig,
    cache: CatalogCache,
    fetcher: F,
}

impl<F: Fetches> CatalogClient<F> {
    /// A client over this configuration, this cache and this fetcher.
    #[must_use]
    pub const fn new(config: RegistryConfig, cache: CatalogCache, fetcher: F) -> Self {
        Self { config, cache, fetcher }
    }

    /// The cache it writes to, so a caller can inspect or clear it.
    #[must_use]
    pub const fn cache(&self) -> &CatalogCache {
        &self.cache
    }

    /// Gets a packument, from a registry if one answers and from the cache if none does.
    ///
    /// # The order, and why the cache is written before it is returned
    ///
    /// A document that was fetched is **stored before it is returned**, so the next call survives a registry that has since
    /// gone away. Storing after the caller has seen the answer would leave a window in which the answer was used and not
    /// remembered — and it is exactly the window in which a machine goes offline.
    ///
    /// A failure to write the cache is **not** a failure of the call: the document in hand is good, and refusing it because
    /// the cache is read-only would turn a disk problem into an inability to install anything.
    ///
    /// # Errors
    ///
    /// [`CatalogError`] when no mirror answers **and** the cache has nothing. A stale entry is not an error — it is
    /// [`Origin::Cache`] with `stale` set — because the design's answer to an unreachable registry is to use it and say so.
    pub fn packument(&self, package: &str, now_ms: i64) -> Result<Fetched, CatalogError> {
        let mirrors = self.config.resolve(package);
        if mirrors.is_empty() {
            return Err(CatalogError::NoRegistry { package: package.to_owned() });
        }

        let mut attempts: Vec<(String, String)> = Vec::new();
        for mirror in mirrors {
            let url = packument_url(&mirror, package);
            match self.fetcher.get(&url) {
                Ok(bytes) => match Packument::parse(package, &bytes) {
                    Ok(packument) => {
                        // The document is cached as **text**, because that is what was signed and what a future reader has
                        // to re-parse: caching the parsed form would mean a change to the parser silently interpreted
                        // documents that a registry never sent.
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            let _ = self.cache.store(package, text, now_ms);
                        }
                        return Ok(Fetched { packument, origin: Origin::Registry { mirror } });
                    }
                    Err(error) => {
                        // ★ A mirror that answers with something else does **not** end the search: the next mirror may have
                        // the real document. It is recorded rather than skipped, because a registry that has started
                        // answering with an error page is worth seeing.
                        attempts.push((mirror, error.to_string()));
                    }
                },
                Err(detail) => attempts.push((mirror, detail)),
            }
        }

        // Every mirror refused. The cache is the design's answer, and a stale entry is used rather than withheld.
        if let Some(cached) = self.cache.load(package, now_ms)? {
            let text = cached.text().to_owned();
            let packument = Packument::parse(package, text.as_bytes()).map_err(|error| {
                CatalogError::Unreadable { package: package.to_owned(), detail: error.to_string() }
            })?;
            return Ok(Fetched {
                packument,
                origin: Origin::Cache { age_ms: cached.age_ms(), stale: cached.is_stale() },
            });
        }

        Err(CatalogError::Unreachable { package: package.to_owned(), attempts })
    }
}

/// The URL a packument lives at.
///
/// `GET {mirror}/{name}` with the name's `/` preserved, which is the npm packument convention: the scoped name is part of the
/// path, and escaping the separator would address a different document.
#[must_use]
pub fn packument_url(mirror: &str, package: &str) -> String {
    let base = mirror.trim_end_matches('/');
    let encoded = package.replace('@', "%40");
    format!("{base}/{encoded}")
}

#[cfg(test)]
mod tests;
