//! The eleven checks a package passes before it is installed, in the order the design document gives them.
//!
//! # Why this is one function and not eleven call sites
//!
//! Because the order is the security argument. Every step is only meaningful if the one before it held: verifying a
//! signature over a manifest nobody has read proves nothing about what the plugin *is*, checking that a plugin's
//! imports are covered by its capabilities is meaningless if the capabilities were never parsed, and a dependency
//! graph is a graph only after every dependency has been read.
//!
//! A caller that assembled these itself would eventually assemble them in a different order, and the symptom of the
//! wrong order is not a failure — it is a package that passes. So the order is here, once, and [`Report`] names which
//! step stopped.
//!
//! # What is deliberately not decided here
//!
//! **Whether the user trusts the publisher.** That is a person's decision, and this reports what it found
//! ([`Stage::PublisherTrust`] passes for an unknown publisher) so the interface can ask. A pipeline that refused an
//! unknown publisher would make the first install from anybody impossible.
//!
//! # The two checks that are this crate's own
//!
//! Everything else delegates: digests and signatures to [`synra_plugin_api::publisher`], the manifest and the
//! capability DSL to [`synra_plugin_api::manifest`], and the import table to [`crate::host_surface`]. The dependency
//! graph and the platform applicability are here because they are about *this host* — what it can run and what it
//! already has — rather than about the package.

use synra_plugin_api::manifest::{Manifest, ManifestContext};
use synra_plugin_api::publisher::{Digests, PluginTrust, PublisherTrustStore, SignatureFile};

use crate::host_surface;

mod graph;

pub use graph::DependencyGraph;

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

/// Why a package was refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The artifact is not the one the source declared.
    #[error("the artifact does not match what its source declared")]
    DigestMismatch,

    /// The signature is not valid, or there is none where one is required.
    #[error("the signature could not be verified: {reason}")]
    BadSignature {
        /// What was wrong.
        reason: String,
    },

    /// The signature is genuine, and it covers different bytes than the package contains.
    ///
    /// # Why this is not [`Self::BadSignature`]
    ///
    /// Because the next step differs. A bad signature is a document, a key or a transfer that was altered — signing
    /// again is the fix. This one is a package and a signature that do not belong together: an artifact rebuilt after
    /// signing, a manifest edited afterwards, a `signature.json` copied from another release. Re-signing is the right
    /// answer there too, but "the signature could not be verified" would send an author to look for a corruption that
    /// is not there.
    #[error("the signature is valid but covers different bytes: {detail}")]
    SignatureCoversOtherBytes {
        /// The first difference, in a sentence naming the file.
        detail: String,
    },

    /// A signature was required and there is none.
    #[error("this package is unsigned and this host requires a signature")]
    Unsigned,

    /// The publisher is one this device refuses.
    #[error("{why}")]
    UntrustedPublisher {
        /// Why, in a sentence a user can act on.
        why: synra_plugin_api::publisher::Untrusted,
    },

    /// The manifest is not valid.
    #[error("the manifest is not valid: {reason}")]
    InvalidManifest {
        /// What the validator said, which names the field.
        reason: String,
    },

    /// A capability is not one the contract mentions.
    #[error("the manifest declares {capability}, which no host function needs")]
    UnknownCapability {
        /// The capability string, as the manifest spells it.
        capability: String,
    },

    /// The plugin was built against a WIT world this host does not have.
    #[error("the plugin was built for {required} and this host provides {provided}")]
    WitIncompatible {
        /// What the plugin declares.
        required: String,
        /// What this host has.
        provided: String,
    },

    /// Actual component bytes do not implement the required plugin world.
    #[error("the component is invalid: {source}")]
    InvalidComponent {
        /// Classified static validation failure.
        source: crate::component::ComponentError,
    },

    /// The artifact imports a function no declared capability covers.
    #[error("the artifact imports {import}, which the manifest's capabilities do not cover")]
    UndeclaredImport {
        /// The import name, in full.
        import: String,
    },

    /// The artifact imports something the host refuses outright.
    #[error("the artifact imports {import}, which this host never provides")]
    ForbiddenImport {
        /// The import name.
        import: String,
    },

    /// A plugin depends on itself, directly or through others.
    #[error("the dependency graph has a cycle: {}", .cycle.join(" -> "))]
    DependencyCycle {
        /// The cycle, starting and ending at the same plugin.
        cycle: Vec<String>,
    },

    /// The archive is outside the bounds.
    #[error("the archive is outside the limits: {detail}")]
    ArchiveTooLarge {
        /// What was found.
        detail: String,
    },

    /// The plugin cannot run on this machine.
    #[error("the plugin needs {needed}, which this host does not support")]
    PlatformUnsupported {
        /// What it needs.
        needed: String,
    },
}

/// What the pipeline is checking.
///
/// # Why the artifact's bytes are here rather than the artifact
///
/// Because the digest step is the first thing that happens to a package — before it has been parsed, before it has
/// been trusted, and before anything has decided it is worth parsing. A type that required a `Manifest` would make
/// "check the bytes" impossible to express without first doing the thing the check exists to protect.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// The manifest file's bytes, exactly as they arrived.
    pub manifest_json: &'a str,
    /// The artifact's bytes.
    pub artifact: &'a [u8],
    /// The digest the source declared for the artifact, if it declared one.
    ///
    /// `None` is not "trust anything": it means the source made no claim, which is the case for a local build an
    /// author is testing. A source that *did* make a claim is what the digest step enforces.
    pub declared_digest: Option<&'a str>,
    /// The artifact's own digest, computed by whoever fetched it.
    pub actual_digest: &'a str,
    /// The digest of the manifest's bytes, in the same SRI form the signature uses.
    ///
    /// A field rather than a value this pipeline computes, because this crate is given bytes and touches neither a
    /// filesystem nor a hash function: whoever read the package is who computes it, and a second implementation of
    /// "which bytes, which encoding" would be a second answer to a question that has one.
    pub manifest_digest: &'a str,
    /// Every artifact the package contains, by file name, with the SRI digest of its bytes.
    ///
    /// The whole set rather than the one artifact the runtime names, because the signature covers the set: a file
    /// added after signing makes a different package, and comparing a single digest would not see it.
    pub artifacts: &'a Digests,
    /// The `signature.json` text, when the package carries one.
    pub signature: Option<&'a str>,
    /// Whether this host requires a signature.
    ///
    /// A field rather than a constant because the answer depends on where the package came from: an author's own
    /// build has no publisher and a registry install has one, and a host that demanded a signature for both would
    /// make a local plugin impossible while a host that demanded neither would make `Unsigned` unrepresentable.
    pub signature_required: bool,
    /// Every plugin this one depends on, and what each of those depends on.
    ///
    /// The whole graph rather than this plugin's edges, because a cycle is a property of the graph: a plugin that
    /// depends on another which depends back on it cannot be detected from either one alone.
    pub dependencies: &'a DependencyGraph,
    /// What this host is.
    pub host: HostFacts,
}

/// What the host can do, for the two checks that are about it rather than about the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// The WIT world this host provides, as the contract declares it.
    pub wit: String,
    /// The platform actions this host can perform.
    ///
    /// A plugin that needs one this host cannot do is not *broken* — it is one whose button will fail on this machine
    /// and work on another, which is a warning rather than a refusal.
    pub actions: Vec<String>,
    /// Whether this host has a network at all.
    pub has_network: bool,
    /// The platform, for a message that names it.
    pub platform: String,
}

impl HostFacts {
    /// A host with everything, which is what a desktop test wants.
    #[must_use]
    pub fn desktop() -> Self {
        Self {
            wit: host_world(),
            actions: host_surface::CAPABILITIES.iter().map(|capability| (*capability).to_owned()).collect(),
            has_network: true,
            platform: "desktop".to_owned(),
        }
    }

    /// A host with nothing, which is what a headless kernel is.
    #[must_use]
    pub fn headless() -> Self {
        Self {
            wit: host_world(),
            actions: Vec::new(),
            has_network: false,
            platform: "headless".to_owned(),
        }
    }
}

/// The WIT world this build implements, as the contract names it.
///
/// `${PACKAGE}/${world}@${VERSION}`, which is how a WIT world is spelled. Read from the generated table rather than
/// written here, so a contract version bump cannot leave the compatibility check behind.
#[must_use]
pub fn host_world() -> String {
    format!(
        "{}@{}",
        host_surface::PACKAGE,
        host_surface::PACKAGE_VERSION
    )
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    /// Which check.
    pub stage: Stage,
    /// What it concluded.
    pub verdict: Verdict,
    /// What was found, in a sentence.
    pub detail: String,
}

/// How a check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// It is fine.
    Pass,
    /// It will not work on this machine, but it is a valid package.
    ///
    /// Distinct from [`Self::Fail`] because the caller's next step differs: a warning is something to *tell the user*
    /// — this plugin's notification button will not work on this device — and a failure is something to refuse.
    Warn,
    /// The package may not be installed.
    Fail,
}

impl Verdict {
    /// A name, for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// What the pipeline concluded.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Every step that ran, in order.
    pub steps: Vec<Step>,
    /// The level of trust the publisher earned, when there was a signature.
    pub trust: Option<PluginTrust>,
    /// The publisher's fingerprint, for a prompt.
    pub fingerprint: Option<synra_plugin_api::publisher::Fingerprint>,
}

impl Report {
    /// Whether the package may be installed.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.steps.iter().all(|step| step.verdict != Verdict::Fail)
    }

    /// The first step that refused, which is the one a caller reports.
    #[must_use]
    pub fn refusal(&self) -> Option<&Step> {
        self.steps.iter().find(|step| step.verdict == Verdict::Fail)
    }

    /// The steps that warned, which are the things to tell a user.
    #[must_use]
    pub fn warnings(&self) -> Vec<&Step> {
        self.steps.iter().filter(|step| step.verdict == Verdict::Warn).collect()
    }

    /// The stage a report stopped at, for a metric label.
    #[must_use]
    pub fn stopped_at(&self) -> Option<Stage> {
        self.refusal().map(|step| step.stage)
    }

    /// A sentence for a log line or a status screen.
    #[must_use]
    pub fn describe(&self) -> String {
        match self.refusal() {
            Some(step) => format!("refused at {}: {}", step.stage.as_str(), step.detail),
            None => {
                let warnings = self.warnings().len();
                if warnings == 0 {
                    format!("all {} checks passed", self.steps.len())
                }
                else {
                    format!("{} checks passed with {warnings} warning(s)", self.steps.len())
                }
            }
        }
    }
}

/// Runs the eleven checks in order, stopping at the first refusal.
///
/// # Why it stops
///
/// Because everything after a refusal is about a package the caller is not going to install, and a report that
/// continued would compute a dependency graph for a plugin whose manifest did not parse. The steps that ran are in
/// the report, so a caller can see how far it got.
///
/// # Errors
///
/// [`VerifyError`] naming the stage that refused. The report is not returned alongside it: the error's variant *is*
/// the stage, and a caller that wanted both would have two ways to ask the same question.
pub fn verify(candidate: &Candidate<'_>, trust: &PublisherTrustStore) -> Result<Report, (Stage, VerifyError)> {
    let mut steps = Vec::with_capacity(Stage::ALL.len());
    let mut earned: Option<(PluginTrust, synra_plugin_api::publisher::Fingerprint)> = None;

    // 1 · The artifact's digest, against what the source declared.
    if let Some(declared) = candidate.declared_digest
        && declared != candidate.actual_digest
    {
        return Err((
            Stage::Digest,
            VerifyError::DigestMismatch,
        ));
    }
    steps.push(Step {
        stage: Stage::Digest,
        verdict: Verdict::Pass,
        detail: match candidate.declared_digest {
            Some(_) => format!("the artifact matches {}", candidate.actual_digest),
            None => "the source declared no digest, so nothing to compare".to_owned(),
        },
    });

    // 2 · The signature, and 3 · what the device makes of the publisher.
    match candidate.signature {
        None if candidate.signature_required => {
            return Err((Stage::Signature, VerifyError::Unsigned));
        }
        None => {
            steps.push(Step {
                stage: Stage::Signature,
                verdict: Verdict::Pass,
                detail: "the package is unsigned and this host does not require a signature".to_owned(),
            });
            steps.push(Step {
                stage: Stage::PublisherTrust,
                verdict: Verdict::Pass,
                detail: "there is no publisher to trust".to_owned(),
            });
        }
        Some(text) => {
            let document = SignatureFile::parse(text).map_err(|error| {
                (Stage::Signature, VerifyError::BadSignature { reason: error.to_string() })
            })?;
            let outcome = document.verify().map_err(|error| {
                (Stage::Signature, VerifyError::BadSignature { reason: error.to_string() })
            })?;
            let synra_plugin_api::publisher::VerifyOutcome::Good { fingerprint } = outcome else {
                return Err((
                    Stage::Signature,
                    VerifyError::BadSignature { reason: "the signature does not verify".to_owned() },
                ));
            };
            // ★ A signature that verifies proves somebody signed *a* subject. This is the step that asks whether it
            // is *this* package's subject — and until it existed, nothing did: the pipeline verified the signature and
            // then asked no further question, so replacing `plugin.wasm` beside a genuine `signature.json` produced a
            // package every check passed. The comparison lives on the subject rather than here because the CLI needs
            // the same one, and "two implementations of one rule" is the shape this codebase keeps removing.
            //
            // Before the trust step, because a publisher prompt about a package that does not match its signature is
            // a question about the wrong thing.
            if let Some(detail) = document.subject.mismatch(candidate.manifest_digest, candidate.artifacts) {
                return Err((Stage::Signature, VerifyError::SignatureCoversOtherBytes { detail }));
            }
            steps.push(Step {
                stage: Stage::Signature,
                verdict: Verdict::Pass,
                detail: format!("signed by {}", fingerprint),
            });

            let trust_level = trust.classify(&document.publisher.id, &fingerprint);
            if let PluginTrust::Untrusted { why } = &trust_level {
                // ★ A refusal rather than a warning: a revoked key and a changed one are decisions already made, and
                // a user cannot consent past either.
                return Err((Stage::PublisherTrust, VerifyError::UntrustedPublisher { why: why.clone() }));
            }
            steps.push(Step {
                stage: Stage::PublisherTrust,
                verdict: Verdict::Pass,
                detail: match &trust_level {
                    PluginTrust::TrustedPublisher => {
                        format!("{} is a publisher this device trusts", document.publisher.id)
                    }
                    // ★ A pass, and deliberately: an unknown publisher is a question for the user, and a pipeline
                    // that failed here would make the first install from anybody impossible.
                    _ => format!("{} is new to this device, so the user will be asked", document.publisher.id),
                },
            });
            earned = Some((trust_level, fingerprint));
        }
    }

    // 4 · The manifest.
    let manifest = Manifest::from_json(candidate.manifest_json).map_err(|error| {
        (Stage::ManifestSchema, VerifyError::InvalidManifest { reason: error.to_string() })
    })?;
    // Manifest consistency and actual component conformance are distinct proofs. This context
    // names the host world; binary imports, exports and signatures are checked from the artifact below.
    let context = ManifestContext {
        host_wit: Some(candidate.host.wit.clone()),
        ..ManifestContext::default()
    };
    manifest.validate(&context).map_err(|error| {
        (
            Stage::ManifestSchema,
            VerifyError::InvalidManifest {
                reason: error.to_string(),
            },
        )
    })?;
    steps.push(Step {
        stage: Stage::ManifestSchema,
        verdict: Verdict::Pass,
        detail: format!("{} {} is a valid manifest", manifest.id, manifest.version),
    });

    // 5 · Every declared capability is one the contract mentions.
    for declared in &manifest.capabilities {
        if !host_surface::is_declared_capability(&declared.cap) {
            return Err((
                Stage::CapabilitySyntax,
                VerifyError::UnknownCapability { capability: declared.cap.clone() },
            ));
        }
    }
    steps.push(Step {
        stage: Stage::CapabilitySyntax,
        verdict: Verdict::Pass,
        detail: format!("{} declared capability(ies) are ones this host knows", manifest.capabilities.len()),
    });

    // 6 · The WIT world.
    if !candidate.host.wit.is_empty() && manifest.wit != candidate.host.wit {
        return Err((
            Stage::WitCompatibility,
            // The host's world is cloned and the plugin's is moved: this is the last use of the manifest's own, and the
            // comparison above already read what it needed.
            VerifyError::WitIncompatible { required: manifest.wit, provided: candidate.host.wit.clone() },
        ));
    }
    // Derive the evidence from actual bytes. Unknown host imports have their own diagnostic;
    // the shared inspector refuses them before checking whole-world subtyping.
    let component =
        crate::component::inspect(candidate.artifact).map_err(|source| match source {
            crate::component::ComponentError::UnsupportedImport { import } => (
                Stage::NoForbiddenImports,
                VerifyError::ForbiddenImport { import },
            ),
            source => (
                Stage::WitCompatibility,
                VerifyError::InvalidComponent { source },
            ),
        })?;
    let imports = component.imports.as_slice();
    steps.push(Step {
        stage: Stage::WitCompatibility,
        verdict: Verdict::Pass,
        detail: format!("built for {}", manifest.wit),
    });

    // 7 · The imports are ones this host has at all.
    //
    // ★ Checked **before** the capability coverage below, and the order is the diagnostic: a package importing
    // `wasi:filesystem` or a function from a newer SDK is one the host does not provide, and reporting that as "no
    // declared capability covers it" would send an author looking through their manifest for a permission to add when
    // what they have is a plugin built against a different host.
    steps.push(Step {
        stage: Stage::NoForbiddenImports,
        verdict: Verdict::Pass,
        detail: format!(
            "all {} actual import(s) are ones this host provides",
            imports.len()
        ),
    });

    // 8 · The imports are covered by the capabilities.
    let mut granted = synra_capability::CapabilitySet::new();
    for declared in &manifest.capabilities {
        // A capability that does not parse was refused at the schema step, which is why this cannot fail here — and a
        // `let _ =` rather than an unwrap, because this function is not allowed to panic on a package's contents.
        let _ = granted.insert_str(&declared.cap);
    }
    let uncovered = host_surface::undeclared_imports(imports, &granted);
    if let Some(import) = uncovered.first() {
        return Err((
            Stage::ImportsWithinCapabilities,
            VerifyError::UndeclaredImport { import: import.clone() },
        ));
    }
    steps.push(Step {
        stage: Stage::ImportsWithinCapabilities,
        verdict: Verdict::Pass,
        detail: format!("{} actual import(s) are all covered", imports.len()),
    });

    // 9 · The dependency graph.
    if let Some(cycle) = candidate.dependencies.cycle_from(&manifest.id.to_string()) {
        return Err((Stage::DependencyAcyclic, VerifyError::DependencyCycle { cycle }));
    }
    steps.push(Step {
        stage: Stage::DependencyAcyclic,
        verdict: Verdict::Pass,
        detail: format!("{} dependency(ies) and no cycle", candidate.dependencies.len()),
    });

    // 10 · The archive, which the caller has already planned — this asks whether one was planned at all.
    if candidate.artifacts.is_empty() {
        return Err((
            Stage::ArchiveLimits,
            VerifyError::ArchiveTooLarge {
                detail: "the package contains no runtime artifacts".to_owned(),
            },
        ));
    }
    steps.push(Step {
        stage: Stage::ArchiveLimits,
        verdict: Verdict::Pass,
        detail: format!("{} bytes of artifact", candidate.artifact.len()),
    });

    // 11 · This platform.
    let needed: Vec<String> = manifest
        .capabilities
        .iter()
        .filter(|declared| declared.cap.starts_with("platform:") || declared.cap.starts_with("network:"))
        .map(|declared| declared.cap.clone())
        .filter(|capability| {
            let known = candidate.host.actions.iter().any(|action| action == capability);
            let networked = candidate.host.has_network && capability.starts_with("network:");
            !known && !networked
        })
        .collect();
    let verdict = if needed.is_empty() { Verdict::Pass } else { Verdict::Warn };
    steps.push(Step {
        stage: Stage::PlatformApplicability,
        verdict,
        detail: if needed.is_empty() {
            format!("everything it declares works on {}", candidate.host.platform)
        }
        else {
            format!("{} cannot do {} on this {}", manifest.id, needed.join(", "), candidate.host.platform)
        },
    });

    let (trust_level, fingerprint) = match earned {
        Some((level, fingerprint)) => (Some(level), Some(fingerprint)),
        None => (None, None),
    };
    Ok(Report { steps, trust: trust_level, fingerprint })
}

#[cfg(test)]
#[path = "../verify_tests.rs"]
mod tests;
