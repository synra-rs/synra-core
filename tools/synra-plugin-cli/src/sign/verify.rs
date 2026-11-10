//! Signature verification against package contents and publisher trust.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use synra_plugin_api::publisher::{self, Fingerprint, SignatureFile};

use super::{SignError, collect_artifacts, read_manifest};
use super::key::hex_decode;

/// What a verification concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The plugin's id.
    pub plugin_id: String,
    /// Its version.
    pub version: String,
    /// Who signed it.
    pub publisher_id: String,
    /// The key's fingerprint, which is what a user compares.
    pub fingerprint: Fingerprint,
    /// What the device makes of the publisher.
    pub trust: publisher::PluginTrust,
}

/// Checks a package's signature against what is on disk.
///
/// # The order the checks happen in, and why
///
/// The document is verified **before** anything is concluded about the publisher, the manifest's artifacts are
/// checked **before** that, and the artifacts' actual digests are checked **last** — each step is only meaningful if
/// the one before it held, and a signature that does not cover what shipped produces a reassuring answer about the
/// wrong bytes.
///
/// # Errors
///
/// [`SignError::Mismatch`] when anything does not agree, [`SignError::Untrusted`] when the publisher is one this
/// device refuses, and [`SignError::DocumentUnreadable`] when the document cannot be read at all.
pub fn verify(
    document_text: &str,
    root: &Path,
    trust: &publisher::PublisherTrustStore,
) -> Result<Verified, SignError> {
    let document = SignatureFile::parse(document_text).map_err(|error| SignError::DocumentUnreadable {
        reason: error.to_string(),
    })?;

    let (manifest, manifest_digest) = read_manifest(root)?;
    if !document.subject.covers(&manifest).is_empty() {
        return Err(SignError::Mismatch);
    }

    let found = collect_artifacts(root, &manifest)?;
    // ★ The same comparison the host's verify pipeline runs (`SigningSubject::matches`), rather than a second
    // hand-written version of it. The manifest digest, every artifact's digest and the "signature covers a subset"
    // question are one question — is this subject this package? — and the two sides had two answers until this call.
    if !document.subject.matches(&manifest_digest, &found) {
        return Err(SignError::Mismatch);
    }

    let publisher::VerifyOutcome::Good { fingerprint } =
        document.verify().map_err(|error| SignError::DocumentUnreadable {
            reason: error.to_string(),
        })?
    else {
        return Err(SignError::Mismatch);
    };

    let trust = trust.classify(&document.publisher.id, &fingerprint);
    if let publisher::PluginTrust::Untrusted { why } = &trust {
        return Err(SignError::Untrusted { why: why.clone() });
    }

    Ok(Verified {
        plugin_id: manifest.id.to_string(),
        version: manifest.version,
        publisher_id: document.publisher.id,
        fingerprint,
        trust,
    })
}

/// Reads the public key an author keeps beside a package, if there is one.
///
/// # Why a package directory has one
///
/// Because an author who signs and then loses the key has no way to notice: the signature they produced is still
/// valid, and every later release would be signed with a key nobody has. The public half beside the package is what a
/// later run compares against, and its absence is not an error — a plugin without one is one whose publisher has not
/// decided to pin anything.
#[must_use]
pub fn expected_fingerprint(root: &Path) -> Option<Fingerprint> {
    let path = root.join("public-key.txt");
    let text = std::fs::read_to_string(path).ok()?;
    let bytes = hex_decode(text.trim()).ok()?;
    let array: [u8; 32] = bytes.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&array).ok().map(|key| Fingerprint::of(&key))
}


