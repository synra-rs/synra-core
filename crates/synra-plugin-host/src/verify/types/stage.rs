/// Which of the eleven checks is running, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Stage {
    /// The artifact's digest agrees with what the source declared.
    Digest,
    /// The signature is valid for the key it names.
    Signature,
    /// The publisher is one this device knows.
    PublisherTrust,
    /// The manifest parses and its fields are valid.
    ManifestSchema,
    /// Every capability the manifest declares is one the contract mentions.
    ///
    /// The manifest's own validator refuses an unknown *domain* — `storag:local:read`, whose domain is not a
    /// capability domain at all — so this is the backstop for a well-formed domain carrying a name no host function
    /// needs. It asks a different question from the validator: not "is this spelled like a capability" but "does
    /// anything in this build act on it".
    CapabilitySyntax,
    /// The WIT world is one this host can run.
    WitCompatibility,
    /// The artifact imports nothing this host does not provide.
    ///
    /// Runs **before** the capability coverage below, and the order is the diagnostic: a package importing
    /// `wasi:filesystem`, or a function from a newer SDK, is one this host does not provide — and reporting that as
    /// "no declared capability covers it" would send an author hunting through their manifest for a permission to add.
    NoForbiddenImports,
    /// Every function the artifact imports is covered by a declared capability.
    ImportsWithinCapabilities,
    /// The dependency graph has no cycle.
    DependencyAcyclic,
    /// The archive is within the size, count and ratio bounds.
    ArchiveLimits,
    /// The plugin can run on this platform.
    PlatformApplicability,
}

impl Stage {
    /// Every stage, in the order they run.
    pub const ALL: &'static [Self] = &[
        Self::Digest,
        Self::Signature,
        Self::PublisherTrust,
        Self::ManifestSchema,
        Self::CapabilitySyntax,
        Self::WitCompatibility,
        Self::NoForbiddenImports,
        Self::ImportsWithinCapabilities,
        Self::DependencyAcyclic,
        Self::ArchiveLimits,
        Self::PlatformApplicability,
    ];

    /// A name, for a report and a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Signature => "signature",
            Self::PublisherTrust => "publisher-trust",
            Self::ManifestSchema => "manifest-schema",
            Self::CapabilitySyntax => "capability-syntax",
            Self::WitCompatibility => "wit-compatibility",
            Self::ImportsWithinCapabilities => "imports-within-capabilities",
            Self::NoForbiddenImports => "no-forbidden-imports",
            Self::DependencyAcyclic => "dependency-acyclic",
            Self::ArchiveLimits => "archive-limits",
            Self::PlatformApplicability => "platform-applicability",
        }
    }

    /// Whether a failure here is something the caller can fix by trying again.
    ///
    /// A digest that disagrees, a signature that does not verify and a cycle in a dependency graph are all facts about
    /// the package: the same bytes produce the same answer, so offering a retry would be offering a button that cannot
    /// work. A fetch that failed and a publisher this device has not seen are the two that change.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::PublisherTrust)
    }

    /// The number of this stage, counting from one, as the design document lists them.
    #[must_use]
    pub fn number(self) -> usize {
        Self::ALL.iter().position(|stage| *stage == self).map_or(0, |index| index + 1)
    }
}
