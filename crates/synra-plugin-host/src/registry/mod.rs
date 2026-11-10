//! The registry: where a package comes from, which mirror answers, and the one failure that stops the search.
//!
//! # The two containers a registry hands back
//!
//! [`ArtifactDigests`] and [`VersionTags`], rather than the standard maps they wrap. Both are this crate's own types
//! because `synra-plugin-host` is semi-stable: naming a standard container in a public signature is a promise about
//! *that* container, which would make "this crate changed no line" compatible with "a consumer's build broke". Each
//! type also says what the thing means — a tag map is looked up by tag, a digest map is looked up by file name — and
//! [`ArtifactDigests`] is deliberately the *same* type the signature subject uses, because the registry's declaration
//! and the publisher's signature are compared to each other.
//!
//! # The rule this module exists for
//!
//! A registry mirror is a **fallback**, and fallbacks are how a security check gets skipped. If a mirror serves a
//! tarball whose bytes do not hash to what the packument declared, trying the next mirror is not resilience — it is
//! asking a different server to tell you what the first one would not, which is what an attacker who can answer for
//! one mirror wants you to do. So:
//!
//! * a **network** failure, a `404` and a `429` fall through to the next mirror;
//! * an **integrity** failure stops: the package is refused, and where it came from is reported.
//!
//! [`FetchFailure::allows_fallback`] is that rule in one place, because a rule that lives at each call site is a rule
//! that gets left out of one of them.
//!
//! # Why the fetching is not here
//!
//! Because what arrives is what matters and the socket is not: a packument is JSON and a tarball is bytes, and both
//! are decided about as values. A type that owned an HTTP client would make every rule below untestable without a
//! server, and the rules — mirror order, integrity, and what may be retried — are where the mistakes are.
//!
//! # Integrity is over the *tarball*
//!
//! Which is the whole download, compressed, exactly as it arrived. The per-artifact digests a signature covers are
//! checked after unpacking by [`crate::verify`]; this is the earlier, coarser check that the thing that arrived is the
//! thing the registry published, and it is the one that has to hold before anything is unpacked at all.

mod digests;

pub use digests::ArtifactDigests;

/// The most a packument may be.
///
/// Eight mebibytes. A packument is metadata: a package with a thousand versions and an inline manifest for each is
/// still well under this, and the bound exists because the response is read into memory before anything parses it —
/// so a server that answers with a stream of bytes is a server that decides how much memory the kernel uses.
pub const MAX_PACKUMENT_BYTES: usize = 8 * 1024 * 1024;

/// The most versions one packument may list.
///
/// Two thousand. A registry is not a place to publish ten thousand versions of one package, and a listing that large
/// is one whose *parse* is the attack.
pub const MAX_VERSIONS: usize = 2_000;

/// The default registry, which is the public one.
pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

mod config;
mod integrity;
mod packument;
mod versions;

pub use config::{FetchFailure, PackagePattern, RegistryConfig, RegistryMirror};
pub use integrity::{Integrity, check_integrity, compare_versions};
pub use packument::{Dist, Packument, SizeBlock, SynraBlock, VersionEntry};
pub use versions::{VersionTags, Versions};

#[cfg(test)]
mod tests;

