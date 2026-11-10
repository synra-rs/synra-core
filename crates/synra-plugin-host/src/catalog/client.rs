//! Registry fetching with cache fallback.

use super::cache::{CacheError, CatalogCache};
use super::super::registry::{Packument, RegistryConfig};

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
#[non_exhaustive]
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




