//! The registry: where a package comes from, which mirror answers, and the one failure that stops the search.
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

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use synra_plugin_api::publisher::SignatureFile;

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

/// Why a package could not be fetched or was refused.
///
/// # `None` is not a variant
///
/// Every failure here has a *further* step or does not, and the type says which through
/// [`FetchFailure::allows_fallback`] rather than by being absent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FetchFailure {
    /// The registry did not answer, or answered with something that is not a packument.
    ///
    /// Retryable on another mirror: a mirror that is down is what a mirror is for.
    #[error("{registry} could not be reached: {reason}")]
    Network {
        /// Which registry.
        registry: String,
        /// What went wrong.
        reason: String,
    },

    /// The package is not there.
    ///
    /// Retryable on another mirror, because registries are not always complete copies of each other — a private
    /// mirror holds the private packages and proxies the rest, and a `404` from it does not mean the package does not
    /// exist.
    #[error("{registry} does not have {package}")]
    NotFound {
        /// Which registry.
        registry: String,
        /// Which package.
        package: String,
    },

    /// The registry is asking us to slow down.
    ///
    /// Retryable, and after a wait rather than immediately — which is what the delay is for.
    #[error("{registry} is rate limiting, and asks for a wait of {retry_after_secs:?} second(s)")]
    RateLimited {
        /// Which registry.
        registry: String,
        /// What it asked for, if it said.
        retry_after_secs: Option<u64>,
    },

    /// ★ The bytes are not the bytes the registry published.
    ///
    /// **Not retryable anywhere.** Either the transport corrupted them or somebody replaced them, and asking a
    /// different mirror to tell you which is what an attacker who can answer for one mirror wants.
    #[error("{registry} served bytes that do not match the integrity it declared")]
    IntegrityMismatch {
        /// Which registry served them.
        registry: String,
        /// What it declared.
        declared: String,
    },

    /// The packument is not one this build can read.
    ///
    /// Retryable on another mirror: a proxy that rewrote the document is a proxy-specific problem, and the package
    /// itself may be perfectly fine.
    #[error("the packument from {registry} could not be read: {reason}")]
    Malformed {
        /// Which registry.
        registry: String,
        /// What was wrong.
        reason: String,
    },

    /// The version asked for does not exist.
    ///
    /// **Not retryable**: a version is a fact about the package, and every mirror has the same versions. A `404` on
    /// another mirror would be the same answer after a longer wait.
    #[error("{package} has no version matching {wanted} (it has {available})")]
    NoSuchVersion {
        /// Which package.
        package: String,
        /// What was asked for.
        wanted: String,
        /// What there is, as a comma-separated list.
        available: String,
    },
}

impl FetchFailure {
    /// Whether trying another mirror could produce a different answer.
    ///
    /// # The two that do not
    ///
    /// An [`Self::IntegrityMismatch`] is the one this method exists for: a fallback there would be a fallback past the
    /// only check that says the bytes are the published ones. [`Self::NoSuchVersion`] is the other: every mirror has
    /// the same versions, so asking again is asking a slower copy of the same answer.
    #[must_use]
    pub const fn allows_fallback(&self) -> bool {
        match self {
            Self::Network { .. }
            | Self::NotFound { .. }
            | Self::RateLimited { .. }
            | Self::Malformed { .. } => true,
            Self::IntegrityMismatch { .. } | Self::NoSuchVersion { .. } => false,
        }
    }

    /// Whether asking the *same* registry again could work.
    ///
    /// A network failure and a rate limit are the two that change on their own. An integrity failure is the same
    /// bytes next time, and a version that does not exist will not.
    #[must_use]
    pub const fn is_retryable_here(&self) -> bool {
        matches!(self, Self::Network { .. } | Self::RateLimited { .. })
    }

    /// Which registry refused.
    #[must_use]
    pub fn registry(&self) -> &str {
        match self {
            Self::Network { registry, .. }
            | Self::NotFound { registry, .. }
            | Self::RateLimited { registry, .. }
            | Self::IntegrityMismatch { registry, .. }
            | Self::Malformed { registry, .. } => registry,
            // A missing version is a fact about the package rather than about a mirror, so there is no registry to
            // name — and naming the one that happened to answer would suggest another might have it.
            Self::NoSuchVersion { .. } => "",
        }
    }
}

/// One place a package may be fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryMirror {
    /// Where it is.
    pub url: String,
    /// Whether it is used at all.
    pub enabled: bool,
    /// Its order: lower is tried first.
    pub priority: u8,
}

impl RegistryMirror {
    /// A mirror at a priority.
    #[must_use]
    pub fn new(url: impl Into<String>, priority: u8) -> Self {
        Self { url: url.into(), enabled: true, priority }
    }

    /// The same mirror, switched off.
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// A pattern a package name is matched against.
///
/// # Why a pattern rather than a list of names
///
/// Because scopes are how packages are grouped: `@acme/chat` and `@acme/notes` belong to one publisher, and a mirror
/// configured for a publisher should serve its next package without anybody editing a configuration file. The two
/// forms are a whole name and a scope with a trailing `*`, which is what the design document's "exact > wildcard"
/// ordering needs and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePattern(String);

impl PackagePattern {
    /// A pattern: a whole name, or a prefix ending in `*`.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self(pattern.into())
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether it matches nothing but the exact name.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        !self.0.ends_with('*')
    }

    /// Whether a package name is covered.
    ///
    /// An exact pattern matches the whole name; a wildcard matches everything beginning with what precedes the `*`.
    /// The comparison is **case-sensitive**, because a package name is a string a registry compares byte for byte and
    /// two names that differ only in case are two packages.
    #[must_use]
    pub fn matches(&self, package: &str) -> bool {
        match self.0.strip_suffix('*') {
            Some(prefix) => package.starts_with(prefix),
            None => self.0 == package,
        }
    }
}

/// Where packages come from, and in what order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryConfig {
    /// The registry a package uses when nothing else covers it.
    pub default: String,
    /// Mirrors, each with a priority.
    pub mirrors: Vec<RegistryMirror>,
    /// Per-package overrides, which win over everything.
    pub overrides: Vec<(PackagePattern, String)>,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self { default: DEFAULT_REGISTRY.to_owned(), mirrors: Vec::new(), overrides: Vec::new() }
    }
}

impl RegistryConfig {
    /// A configuration with only the public registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a mirror.
    #[must_use]
    pub fn with_mirror(mut self, mirror: RegistryMirror) -> Self {
        self.mirrors.push(mirror);
        self
    }

    /// Adds an override.
    #[must_use]
    pub fn with_override(mut self, pattern: PackagePattern, url: impl Into<String>) -> Self {
        self.overrides.push((pattern, url.into()));
        self
    }

    /// Where a package may be fetched from, in the order to try.
    ///
    /// # The order, which is the design document's
    ///
    /// 1. an override that names the package exactly;
    /// 2. then overrides with a wildcard, in the order they were declared — later ones do not win, because
    ///    "last one configured" is an ordering nobody reading a configuration file can predict;
    /// 3. then every enabled mirror by priority, ties broken by declaration order;
    /// 4. and the default last.
    ///
    /// An override is a *decision* about where a package lives, so the list it produces is one entry: falling back
    /// from a mirror the user configured for a package to a public registry is how a private package's name gets
    /// asked for in public.
    #[must_use]
    pub fn resolve(&self, package: &str) -> Vec<String> {
        for (pattern, url) in &self.overrides {
            if pattern.is_exact() && pattern.matches(package) {
                return vec![url.clone()];
            }
        }
        for (pattern, url) in &self.overrides {
            if !pattern.is_exact() && pattern.matches(package) {
                return vec![url.clone()];
            }
        }

        let mut enabled: Vec<&RegistryMirror> = self.mirrors.iter().filter(|mirror| mirror.enabled).collect();
        // Sorted by priority, and *stably*, so two mirrors at the same priority are tried in the order they were
        // configured rather than in whatever order the sort happened to leave them.
        enabled.sort_by_key(|mirror| mirror.priority);

        let mut order: Vec<String> = enabled.into_iter().map(|mirror| mirror.url.clone()).collect();
        if !order.contains(&self.default) {
            order.push(self.default.clone());
        }
        order
    }
}

/// What a registry says about one version of a package.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionEntry {
    /// The version, as the registry spells it.
    pub version: String,
    /// Where the tarball is, and what it must hash to.
    pub dist: Dist,
}

/// Where the bytes are and what they must be.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dist {
    /// The tarball's URL.
    pub tarball: String,
    /// Its integrity, as an SRI string.
    ///
    /// `Option` because the field is what npm *should* always send and what a private mirror sometimes omits. A
    /// missing integrity is not a licence to skip the check: [`Integrity::parse`] refuses an empty string, and a
    /// caller that has no integrity has nothing to verify against — which is a decision for the pipeline above, not
    /// something this type invents an answer to.
    #[serde(default)]
    pub integrity: Option<String>,
    /// The `synra` block the registry carries, when it carries one.
    #[serde(default)]
    pub synra: Option<SynraBlock>,
}

/// What a registry says about a package *as a Synra plugin*.
///
/// # Why this is here and not left to the manifest
///
/// Because it is what lets an interface show what a plugin asks for **before** the artifact is downloaded. A user
/// deciding whether to install something should not have to fetch a megabyte of Wasm to find out that it wants their
/// clipboard.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SynraBlock {
    /// The signature document, inline.
    #[serde(default)]
    pub signature: Option<SignatureFile>,
    /// The digest of the manifest, as an SRI string.
    #[serde(default)]
    pub manifest_digest: Option<String>,
    /// Each artifact's digest, by file name.
    #[serde(default)]
    pub artifacts: BTreeMap<String, String>,
    /// What the plugin asks for, so a catalog can filter without downloading.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// What the artifact weighs, so a prompt can say so.
    #[serde(default)]
    pub size: Option<SizeBlock>,
}

/// How large the parts of a package are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SizeBlock {
    /// The headless artifact.
    #[serde(default)]
    pub wasm: u64,
    /// The interface bundle.
    #[serde(default)]
    pub ui: u64,
}

/// Everything a registry says about a package.
///
/// The renaming is **not** uniform, and deliberately: the surrounding document is npm's and its field is spelled
/// `dist-tags` with a hyphen, while the `synra` block this design adds is camel case to match the manifest and the IPC
/// surface. A single `rename_all` would have to be wrong about one of them, and being wrong about `dist-tags` means a
/// package whose `latest` tag is silently absent.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Packument {
    /// The package's name.
    pub name: String,
    /// Which version each tag points at, such as `latest`.
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: BTreeMap<String, String>,
    /// Every published version.
    #[serde(default)]
    pub versions: BTreeMap<String, VersionEntry>,
}

impl Packument {
    /// Parses a packument.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::Malformed`] when it is not JSON, is larger than [`MAX_PACKUMENT_BYTES`], lists more than
    /// [`MAX_VERSIONS`] versions, or does not have the shape a packument has — each with the reason, because "could
    /// not read the packument" leaves whoever is configuring a mirror with nothing to check.
    pub fn parse(registry: &str, bytes: &[u8]) -> Result<Self, FetchFailure> {
        let malformed = |reason: String| FetchFailure::Malformed { registry: registry.to_owned(), reason };
        if bytes.len() > MAX_PACKUMENT_BYTES {
            return Err(malformed(format!(
                "it is {} bytes, and the limit is {MAX_PACKUMENT_BYTES}",
                bytes.len()
            )));
        }
        let packument: Self = serde_json::from_slice(bytes).map_err(|error| malformed(error.to_string()))?;
        if packument.name.is_empty() {
            return Err(malformed("it names no package".to_owned()));
        }
        if packument.versions.len() > MAX_VERSIONS {
            return Err(malformed(format!(
                "it lists {} versions, and the limit is {MAX_VERSIONS}",
                packument.versions.len()
            )));
        }
        Ok(packument)
    }

    /// The version a tag points at.
    ///
    /// `None` for a tag the registry does not have, which is the ordinary answer for `next` on a package that has
    /// never published one.
    #[must_use]
    pub fn tagged(&self, tag: &str) -> Option<&VersionEntry> {
        self.dist_tags.get(tag).and_then(|version| self.versions.get(version))
    }

    /// The newest version, as a registry orders them.
    ///
    /// # Why this is string ordering and not semantic
    ///
    /// Because a packument's `versions` is a map and JSON maps have no order, so "newest" has to be *decided*. The
    /// registry settles it with `dist-tags.latest`, and that is what [`Self::tagged`] reads. This fallback exists for
    /// a mirror that sent no tags, and it compares by the numeric components so that `1.10.0` sorts after `1.9.0`
    /// rather than before it — which plain string ordering gets wrong and which is the mistake that ships an old
    /// version to everybody.
    #[must_use]
    pub fn newest(&self) -> Option<&VersionEntry> {
        self.versions
            .values()
            .max_by(|first, second| compare_versions(&first.version, &second.version))
    }

    /// The version a caller asked for.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::NoSuchVersion`] naming what the package does have, because the caller's next step is to pick
    /// one of them.
    pub fn version(&self, package: &str, wanted: &str) -> Result<&VersionEntry, FetchFailure> {
        if let Some(found) = self.versions.get(wanted) {
            return Ok(found);
        }
        // A range is not resolved here: choosing a version from a requirement needs the semver rules, and they live
        // where the rest of the manifest's version handling does. What this does is the exact case and the tag case,
        // and it says what it has rather than guessing.
        if let Some(found) = self.tagged(wanted) {
            return Ok(found);
        }
        Err(FetchFailure::NoSuchVersion {
            package: package.to_owned(),
            wanted: wanted.to_owned(),
            available: self.versions.keys().cloned().collect::<Vec<String>>().join(", "),
        })
    }
}

/// Compares two version strings by their numeric parts.
///
/// Not a semver implementation, and deliberately: the only question this answers is "which of these two is newer",
/// for a registry that sent no `latest` tag. A pre-release is treated as *older* than its release, which is the one
/// semantic rule that matters for picking a default and the one a plain comparison gets wrong.
#[must_use]
pub fn compare_versions(first: &str, second: &str) -> core::cmp::Ordering {
    let parts = |version: &str| -> (Vec<u64>, bool) {
        let (core, pre) = version.split_once('-').map_or((version, ""), |(core, pre)| (core, pre));
        let numbers = core
            .split(['.', '+'])
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect();
        (numbers, !pre.is_empty())
    };
    let (left, left_pre) = parts(first);
    let (right, right_pre) = parts(second);
    match left.cmp(&right) {
        core::cmp::Ordering::Equal => {
            // A release is newer than its own pre-releases.
            match (left_pre, right_pre) {
                (true, false) => core::cmp::Ordering::Less,
                (false, true) => core::cmp::Ordering::Greater,
                _ => core::cmp::Ordering::Equal,
            }
        }
        other => other,
    }
}

/// A digest a downloaded artifact must hash to.
///
/// # The algorithm is named in the digest
///
/// An SRI string is `algorithm-base64`, and the algorithm is part of it. A verifier that had to be told which
/// algorithm to use would be a verifier that could be told the wrong one — and the failure mode of "check it with
/// MD5" is a check that passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    /// The algorithm, as the string spells it: `sha256`, `sha384` or `sha512`.
    pub algorithm: String,
    /// The base64 digest, without its padding — which is how SRI spells one.
    pub digest: String,
}

impl Integrity {
    /// Parses an SRI string.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::Malformed`] when the string is not `algorithm-base64`, names an algorithm this build cannot
    /// compute, or carries a digest of the wrong length for it. Each is refused rather than ignored: an integrity
    /// string nobody can check is one that reads as "no integrity", and that is the answer that lets a substituted
    /// tarball through.
    pub fn parse(registry: &str, text: &str) -> Result<Self, FetchFailure> {
        let malformed = |reason: String| FetchFailure::Malformed { registry: registry.to_owned(), reason };
        let (algorithm, digest) = text
            .split_once('-')
            .ok_or_else(|| malformed(format!("`{text}` is not an SRI digest")))?;
        let algorithm = algorithm.to_lowercase();
        let expected = match algorithm.as_str() {
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            other => {
                return Err(malformed(format!("`{other}` is not a digest this build computes")));
            }
        };
        if digest.is_empty() {
            return Err(malformed("the digest is empty".to_owned()));
        }
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(digest.trim_end_matches('='))
            .map_err(|error| malformed(format!("the digest is not base64: {error}")))?;
        if decoded.len() != expected {
            return Err(malformed(format!(
                "a {algorithm} digest is {expected} bytes and this one is {}",
                decoded.len()
            )));
        }
        Ok(Self { algorithm, digest: digest.trim_end_matches('=').to_owned() })
    }

    /// Whether some bytes hash to this digest.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        let computed = match self.algorithm.as_str() {
            "sha256" => Sha256::digest(bytes).to_vec(),
            "sha384" => Sha384::digest(bytes).to_vec(),
            "sha512" => Sha512::digest(bytes).to_vec(),
            _ => return false,
        };
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(computed);
        // Compared as encoded text rather than as bytes, so a digest with different padding that a mirror sent is the
        // same digest.
        encoded.trim_end_matches('=') == self.digest
    }

    /// The digest as it is written.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}-{}", self.algorithm, self.digest)
    }
}

/// Checks a downloaded tarball against what the registry declared.
///
/// # Errors
///
/// [`FetchFailure::IntegrityMismatch`], which is the failure that must never fall through to another mirror, and
/// [`FetchFailure::Malformed`] when the registry declared an integrity nobody can check.
pub fn check_integrity(registry: &str, declared: &str, bytes: &[u8]) -> Result<Integrity, FetchFailure> {
    let integrity = Integrity::parse(registry, declared)?;
    if !integrity.matches(bytes) {
        return Err(FetchFailure::IntegrityMismatch {
            registry: registry.to_owned(),
            declared: integrity.as_str(),
        });
    }
    Ok(integrity)
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
