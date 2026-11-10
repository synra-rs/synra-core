//! `sign`: the signature a published package carries, and what it covers.
//!
//! # What a signature is for here
//!
//! The design document's trust model has three levels, and the middle one is "signed, by a publisher the user has
//! already confirmed". A signature is what makes the *next* install from that publisher verifiable without asking
//! again — so the thing being signed has to be exactly the thing that could differ between two downloads.
//!
//! # What is covered, and why it is digests rather than bytes
//!
//! Every artifact the manifest names, by file name **and** digests, plus the digest of the manifest itself. That is
//! [`SigningSubject`], and it is the same type the host verifies with — the format is not this tool's, and a change to
//! it is a change to the contract.
//!
//! The first version of this tool signed a canonical encoding of the artifact's *bytes*, which worked and had two
//! problems: a signature that moved with the file's name rather than its content, and a second format the host would
//! have had to understand. Digests make the signed statement about the bytes and nothing else, and a manifest digest
//! covers the part that decides what the plugin *is* — a plugin whose manifest asks for `storage` is a different
//! plugin even when the `.wasm` is identical.
//!
//! # What is deliberately not here
//!
//! No key storage, no keyring, no passphrase prompt. A key is a file the author names, and a tool that generated one
//! and hid it would be a tool whose keys the author cannot back up — which is how a publisher loses the ability to
//! ship an update to a plugin users already trust.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use synra_plugin_api::manifest::Manifest;
use synra_plugin_api::publisher::{self, SigningSubject, Untrusted};

use crate::package_artifacts::artifact_names;

/// Why a signature could not be produced or checked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The key file could not be read.
    #[error("the key at {path} could not be read: {reason}")]
    KeyUnreadable {
        /// Where it is.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// The key file is not a key.
    ///
    /// The format is 32 bytes of lowercase hex, one line — deliberately the simplest thing an author can produce, and
    /// printable so they can back it up somewhere a file cannot go.
    #[error("the key at {path} is not 32 bytes of hex: {reason}")]
    KeyMalformed {
        /// Where it is.
        path: String,
        /// What was found.
        reason: String,
    },

    /// The manifest could not be read or does not parse.
    #[error("the manifest at {path} could not be read as a manifest: {reason}")]
    ManifestUnreadable {
        /// Where it is.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// The artifact is missing.
    #[error("the artifact {path} does not exist, so there is nothing to sign")]
    NoArtifact {
        /// Where it should be.
        path: String,
    },

    /// The artifact could not be read.
    #[error("the artifact at {path} could not be read: {reason}")]
    ArtifactUnreadable {
        /// Where it is.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// The signature document could not be read.
    #[error("the signature could not be read: {reason}")]
    DocumentUnreadable {
        /// What the parser said.
        reason: String,
    },

    /// A signature did not verify.
    ///
    /// The one answer for the three ways it can fail — the artifact changed, the manifest changed, or the key is not
    /// the publisher's — because a verifier that said *which* would tell an attacker which part to change.
    #[error("the signature does not verify against this plugin")]
    Mismatch,

    /// The signature is by a key this device refuses.
    #[error("{why}")]
    Untrusted {
        /// Why, in a sentence a user can act on.
        why: Untrusted,
    },
}

/// What a signature covers, and the plugin it belongs to.
///
/// # Why the subject is the contract's own type
///
/// Because the host verifies with it. A tool that built its own subject would be a second definition of what a
/// signature is over, and the two would drift — with the symptom being a signature that this tool made and the host
/// refuses, which an author has no way to diagnose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedContent {
    /// The plugin's id, exactly as the manifest spells it.
    pub plugin_id: String,
    /// Its version, exactly as the manifest spells it.
    pub version: String,
    /// Who is publishing it, as the manifest declares.
    pub publisher_id: String,
    /// What was signed: the manifest's digest and every artifact's.
    pub subject: SigningSubject,
}

impl SignedContent {
    /// Reads what a plugin's signature covers.
    ///
    /// # Errors
    ///
    /// [`SignError`] when the manifest or an artifact cannot be read.
    ///
    /// # The artifacts come from the manifest
    ///
    /// Because the manifest is what the kernel reads, so signing a file the kernel will not load would be a signature
    /// over the wrong bytes — and it would verify, which is worse.
    pub fn read(root: &Path) -> Result<Self, SignError> {
        let (manifest, manifest_digest) = read_manifest(root)?;
        let artifacts = collect_artifacts(root, &manifest)?;

        Ok(Self {
            plugin_id: manifest.id.to_string(),
            version: manifest.version,
            publisher_id: manifest.publisher.id,
            subject: SigningSubject { manifest: manifest_digest, artifacts },
        })
    }
}

/// Reads the manifest and its digest.
///
/// The digest is over **the file's bytes**, not over a re-serialisation: the host hashes the bytes it received, and a
/// digest computed from a parsed-and-printed form would be a digest of something nobody downloaded.
pub(super) fn read_manifest(root: &Path) -> Result<(Manifest, String), SignError> {
    let path = root.join("manifest.json");
    let text = std::fs::read_to_string(&path).map_err(|error| SignError::ManifestUnreadable {
        path: path.display().to_string(),
        reason: error.to_string(),
    })?;
    let manifest = Manifest::from_json(&text).map_err(|error| SignError::ManifestUnreadable {
        path: path.display().to_string(),
        reason: error.to_string(),
    })?;
    Ok((manifest, sri_digest(text.as_bytes())))
}

/// Every artifact the manifest names, by file name, with its digest.
pub(super) fn collect_artifacts(root: &Path, manifest: &Manifest) -> Result<publisher::Digests, SignError> {
    let mut artifacts = publisher::Digests::new();
    for name in artifact_names(manifest) {
        let path = root.join(&name);
        if !path.exists() {
            return Err(SignError::NoArtifact { path: path.display().to_string() });
        }
        let bytes = read_artifact(&path)?;
        artifacts.insert(name, sri_digest(&bytes));
    }
    Ok(artifacts)
}

/// A digest in the form the manifest's own field uses.
///
/// `sha256-<base64>`, which is what an SRI string is. Written here rather than borrowed from the protocol crate's
/// `SriDigest` because the two disagree about padding: SRI drops it, and a signature computed over a padded form would
/// not match the one a registry publishes.
fn sri_digest(bytes: &[u8]) -> String {
    use base64::Engine as _;
    let digest = Sha256::digest(bytes);
    format!("sha256-{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
}

/// Reads an artifact, which may be a file or a directory.
///
/// A UI bundle is a directory, and its bytes are what a download could differ in — so the digest is over its files in
/// **sorted** order, because a directory listing's order is not defined and an unsorted walk would produce a digest
/// that changed between runs on the same content.
fn read_artifact(path: &Path) -> Result<Vec<u8>, SignError> {
    if path.is_dir() {
        let mut entries = Vec::new();
        collect_files(path, path, &mut entries).map_err(|error| SignError::ArtifactUnreadable {
            path: path.display().to_string(),
            reason: error,
        })?;
        entries.sort_by(|first, second| first.0.cmp(&second.0));

        let mut out = Vec::new();
        for (relative, absolute) in entries {
            let bytes = std::fs::read(&absolute).map_err(|error| SignError::ArtifactUnreadable {
                path: absolute.display().to_string(),
                reason: error.to_string(),
            })?;
            // The *path* is covered as well as the contents: a bundle with the same files under different names is a
            // different plugin, and a digest over contents alone would let them be rearranged.
            let name = relative.as_bytes();
            out.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        return Ok(out);
    }

    std::fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SignError::NoArtifact { path: path.display().to_string() }
        }
        else {
            SignError::ArtifactUnreadable {
                path: path.display().to_string(),
                reason: error.to_string(),
            }
        }
    })
}

/// Collects a directory's files, as `(relative, absolute)` pairs.
fn collect_files(root: &Path, directory: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    let entries = std::fs::read_dir(directory).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        out.push((relative, path));
    }
    Ok(())
}

mod key;
mod verify;

pub use key::SigningKeyFile;
#[cfg(test)]
pub(super) use key::hex_encode;
pub use verify::{Verified, expected_fingerprint, verify};

#[cfg(test)]
mod tests;

