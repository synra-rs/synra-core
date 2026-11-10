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

/// How long a cached packument may be used as though it were current.
///
/// The design's number, in milliseconds. Past it the document is still returned — see the module documentation on stale
/// entries — but it is marked, because a catalogue from eight days ago is a different thing from one from eight minutes ago
/// and only the caller knows whether the difference matters to what it is about to do.
pub const DEFAULT_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

mod cache;
mod client;

pub use cache::{CacheError, Cached, CatalogCache};
pub use client::{CatalogClient, CatalogError, Fetches, Fetched, Origin, packument_url};

#[cfg(test)]
mod tests;

