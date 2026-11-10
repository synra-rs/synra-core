use synra_plugin_api::manifest::{Manifest, ManifestContext};
use synra_plugin_api::publisher::{PluginTrust, PublisherTrustStore, SignatureFile};

use crate::host_surface;

use super::{Candidate, Report, Stage, Step, VerifyError, Verdict};

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
