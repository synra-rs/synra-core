//! Registry selection and fallback policy.

use super::DEFAULT_REGISTRY;

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


