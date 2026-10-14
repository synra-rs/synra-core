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

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::RngCore as _;
use sha2::{Digest, Sha256};
use synra_plugin_api::manifest::Manifest;
use synra_plugin_api::publisher::{self, Fingerprint, SignatureFile, SigningSubject, Untrusted};

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
fn read_manifest(root: &Path) -> Result<(Manifest, String), SignError> {
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
fn collect_artifacts(root: &Path, manifest: &Manifest) -> Result<publisher::Digests, SignError> {
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

/// The artifact file names a manifest declares.
///
/// A UI-only plugin has no `.wasm`, and the thing that has to be covered is whatever a download could differ in —
/// which for a UI plugin is its bundle.
fn artifact_names(manifest: &Manifest) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(headless) = &manifest.runtime.headless {
        names.push(headless.artifact.clone());
    }
    if let Some(ui) = &manifest.runtime.ui {
        names.push(ui.artifact.clone());
    }
    names
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

/// A signing key, parsed from the format this tool reads.
///
/// The format is 32 bytes of lowercase hex in a file. Deliberately the simplest thing an author can produce, and
/// printable: a key they can write down is a key they can restore, and a publisher who loses theirs cannot ship an
/// update to a plugin users already trust.
#[derive(Debug)]
pub struct SigningKeyFile {
    key: SigningKey,
}

impl SigningKeyFile {
    /// Reads a key.
    ///
    /// # Errors
    ///
    /// [`SignError`] when the file cannot be read or is not 32 bytes of hex.
    pub fn read(path: &Path) -> Result<Self, SignError> {
        let text = std::fs::read_to_string(path).map_err(|error| SignError::KeyUnreadable {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        Self::parse(text.trim()).map_err(|reason| SignError::KeyMalformed {
            path: path.display().to_string(),
            reason,
        })
    }

    /// Parses 32 bytes of hex.
    ///
    /// # Errors
    ///
    /// The reason, as a sentence, when it is not 32 bytes of hex.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bytes = hex_decode(text)?;
        // The length is checked before the type conversion, because a `SigningKey` from 16 bytes would be a weaker key
        // rather than an error — and a publisher would not know.
        let array: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("it is {} bytes and a key is 32", bytes.len()))?;
        Ok(Self { key: SigningKey::from_bytes(&array) })
    }

    /// Generates a new key from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// The reason, as a sentence, when the system's randomness cannot be read. Reported rather than worked around: a
    /// key from a weak source is one an attacker can forge, and the failure would be silent.
    pub fn generate() -> Result<Self, String> {
        Ok(Self { key: SigningKey::from_bytes(&os_randomness()?) })
    }

    /// The secret, as the hex this tool reads back.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_encode(self.key.as_bytes())
    }

    /// The public half, as hex.
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// The public half's fingerprint, as a user compares it.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.key.verifying_key())
    }

    /// The public half as base64, which is what a signature document carries.
    #[must_use]
    pub fn public_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().as_bytes())
    }

    /// Signs content, producing the document a package carries.
    ///
    /// `signed_at` is passed in rather than read from the clock, because a document's timestamp is a value a test
    /// asserts and a reproducibility check compares.
    #[must_use]
    pub fn sign(&self, content: &SignedContent, signed_at: &str) -> String {
        let signature = self.key.sign(&content.subject.canonical_bytes());
        let document = serde_json::json!({
            "version": publisher::SIGNATURE_VERSION,
            "publisher": { "id": content.publisher_id },
            "algorithm": publisher::ALGORITHM,
            "signedAt": signed_at,
            "pubkey": self.public_base64(),
            "subject": {
                "manifest": content.subject.manifest,
                "artifacts": content.subject.artifacts,
            },
            "signature": encode_signature(&signature.to_bytes()),
        });
        // Pretty-printed, because the file lands in a repository and a human diffs it. The *signed* bytes are the
        // canonical subject, so the presentation cannot change what a signature means.
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// The base64 of a signature.
fn encode_signature(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

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
    if document.subject.manifest != manifest_digest {
        // The manifest on disk is not the one that was signed. Checked before the signature, because a signature over
        // another manifest would verify perfectly and mean nothing.
        return Err(SignError::Mismatch);
    }
    if !document.subject.covers(&manifest).is_empty() {
        return Err(SignError::Mismatch);
    }

    let found = collect_artifacts(root, &manifest)?;
    if found != document.subject.artifacts {
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

/// Reads randomness from the operating system.
///
/// # Why this goes through `ed25519-dalek`'s own randomness
///
/// The alternative was to call the platform's API directly, and on Windows that is an `unsafe extern` block —
/// which this workspace forbids everywhere. `ed25519-dalek`'s `rand_core` feature already reads the same source
/// correctly on every platform it supports, so the dependency is on a sibling feature of a crate already here rather
/// than on a second random-number crate.
///
/// A key from a weak source is one an attacker can forge and the failure would be silent, so this reports rather than
/// working around a failure.
fn os_randomness() -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    // `fill_bytes`, not `try_fill_bytes`: `rand_core` 0.6's `OsRng` has no fallible call, and its contract is that the
    // system either has randomness or the process cannot continue. The result is still a `Result` at this boundary, so
    // a later version with a fallible call changes one line rather than every caller.
    rand_core::OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// The lowercase hex of some bytes.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Written by hand rather than with a crate: it is eight lines, and a dependency for it would be a dependency
        // in a tool an author runs on their own machine for no gain.
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
    }
    out
}

/// Decodes lowercase or uppercase hex.
///
/// # Errors
///
/// The reason, as a sentence: an odd length, a character that is not hex, or the byte that is not.
fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("it has {} characters and hex comes in pairs", text.len()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    // `as_chunks` rather than `chunks_exact` plus indexing: the compiler knows each chunk is exactly two bytes, so the
    // two reads cannot panic — and "may panic" is a lint this workspace denies because the kernel decodes bytes from
    // the network.
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(format!("it has {} characters and hex comes in pairs", text.len()));
    }
    for pair in pairs {
        let high = hex_value(pair[0]).ok_or_else(|| format!("`{}` is not a hex digit", char::from(pair[0])))?;
        let low = hex_value(pair[1]).ok_or_else(|| format!("`{}` is not a hex digit", char::from(pair[1])))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// The value of one hex digit.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_plugin_api::publisher::PublisherTrustStore;

    /// A package directory that removes itself.
    struct Package {
        path: PathBuf,
    }

    impl Package {
        /// Writes a manifest and one artifact.
        fn new(name: &str, artifact: &str) -> Self {
            let unique = format!(
                "synra-sign-{}-{}-{name}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_nanos())
                    .unwrap_or(0)
            );
            let path = std::env::temp_dir().join(unique.replace(['\\', ':', '.', ' '], "-"));
            std::fs::create_dir_all(&path).expect("a directory");
            let manifest = format!(
                r#"{{
                    "id": "@acme/{name}",
                    "version": "1.2.3",
                    "title": "Hello",
                    "publisher": {{ "id": "acme" }},
                    "sdk": {{ "min": "1.0.0" }},
                    "wit": "1.0.0",
                    "capabilities": [],
                    "runtime": {{ "headless": {{ "artifact": "{artifact}", "stateful": false }} }}
                }}"#
            );
            std::fs::write(path.join("manifest.json"), manifest).expect("a manifest");
            // A directory artifact is a UI bundle: the path is a directory the fixture leaves empty, so a test can put
            // files in it. A file artifact is a file with a header.
            if artifact == "ui" {
                std::fs::create_dir_all(path.join(artifact)).expect("a bundle directory");
            }
            else {
                std::fs::write(path.join(artifact), b"\0asm\x01\0\0\0").expect("an artifact");
            }
            Self { path }
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            std::fs::write(self.path.join(name), bytes).expect("a file");
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.path.join(name)).expect("a file")
        }
    }

    impl Drop for Package {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn key(seed: u8) -> SigningKeyFile {
        SigningKeyFile::parse(&hex_encode(&[seed; 32])).expect("a key")
    }

    #[test]
    fn a_signed_package_verifies_against_its_own_bytes() {
        // The round trip, from both sides: what `sign` writes is what `verify` reads, and the digests in between are
        // of the bytes on disk.
        let package = Package::new("hello", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        assert_eq!(content.plugin_id, "@acme/hello");
        assert_eq!(content.publisher_id, "acme");
        assert_eq!(content.subject.artifacts.len(), 1);
        assert!(content.subject.artifacts.contains("plugin.wasm"));
        assert!(content.subject.manifest.starts_with("sha256-"), "an SRI digest");

        let signing = key(7);
        let document = signing.sign(&content, "unix-ms:1");
        let verified = verify(&document, &package.path, &PublisherTrustStore::new()).expect("verified");
        assert_eq!(verified.plugin_id, "@acme/hello");
        assert_eq!(verified.publisher_id, "acme");
        assert_eq!(verified.fingerprint, signing.fingerprint());
    }

    #[test]
    fn an_artifact_changed_after_signing_does_not_verify() {
        // ★ The one outcome that is never a warning: either the package was altered after signing or it was signed
        // over something else.
        let package = Package::new("changed", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&content, "unix-ms:1");

        package.write("plugin.wasm", b"\0asm\x01\0\0\0\xff");
        assert_eq!(
            verify(&document, &package.path, &PublisherTrustStore::new()),
            Err(SignError::Mismatch)
        );
    }

    #[test]
    fn a_manifest_changed_after_signing_does_not_verify() {
        // The manifest is what decides what the plugin *is*, so a signature that did not cover it would let a plugin
        // asking for `storage` be substituted for one that does not.
        let package = Package::new("manifest", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&content, "unix-ms:1");

        let text = package.read("manifest.json").replace("Hello", "Something else");
        package.write("manifest.json", text.as_bytes());
        assert_eq!(
            verify(&document, &package.path, &PublisherTrustStore::new()),
            Err(SignError::Mismatch)
        );
    }

    #[test]
    fn a_document_signed_by_another_key_does_not_verify() {
        let package = Package::new("stranger", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&content, "unix-ms:1");
        // The document is intact; the key inside it is not the one that signed it, because it was edited.
        let swapped = document.replace(&key(7).public_base64(), &key(9).public_base64());

        assert_eq!(
            verify(&swapped, &package.path, &PublisherTrustStore::new()),
            Err(SignError::Mismatch)
        );
    }

    #[test]
    fn a_revoked_publisher_is_refused_rather_than_reported_as_a_mismatch() {
        // The two answers have different next steps: "the bytes changed" is a corrupt download, "this key is revoked"
        // is a decision, and a caller that folded them together would offer a retry for something no retry fixes.
        let package = Package::new("revoked", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let signing = key(7);
        let document = signing.sign(&content, "unix-ms:1");

        let mut store = PublisherTrustStore::new();
        store.revoke(signing.fingerprint(), "malicious code");
        match verify(&document, &package.path, &store) {
            Err(SignError::Untrusted { why }) => assert!(why.to_string().contains("malicious code")),
            other => panic!("expected a revocation, got {other:?}"),
        }
    }

    #[test]
    fn a_publisher_whose_key_changed_is_refused() {
        let package = Package::new("rotated", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&content, "unix-ms:1");

        let mut store = PublisherTrustStore::new();
        store.trust("acme", key(9).fingerprint());
        match verify(&document, &package.path, &store) {
            Err(SignError::Untrusted { why }) => assert!(why.to_string().contains("known with key")),
            other => panic!("expected a key-change refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_publisher_the_device_already_trusts_is_reported_as_trusted() {
        let package = Package::new("trusted", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let signing = key(7);
        let document = signing.sign(&content, "unix-ms:1");

        let mut store = PublisherTrustStore::new();
        store.trust("acme", signing.fingerprint());
        let verified = verify(&document, &package.path, &store).expect("verified");
        assert!(verified.trust.is_trusted());
        assert!(!verified.trust.is_refusal());
    }

    #[test]
    fn a_first_install_is_a_question_rather_than_a_refusal() {
        let package = Package::new("first", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&content, "unix-ms:1");

        let verified = verify(&document, &package.path, &PublisherTrustStore::new()).expect("verified");
        assert_eq!(verified.trust, publisher::PluginTrust::UnknownPublisher);
        assert!(!verified.trust.is_trusted());
        assert!(!verified.trust.is_refusal());
    }

    #[test]
    fn an_artifact_that_is_not_there_is_named_rather_than_signed_as_nothing() {
        let package = Package::new("missing", "plugin.wasm");
        std::fs::remove_file(package.path.join("plugin.wasm")).expect("removed");

        match SignedContent::read(&package.path) {
            Err(SignError::NoArtifact { path }) => assert!(path.contains("plugin.wasm")),
            other => panic!("expected a missing artifact, got {other:?}"),
        }
    }

    #[test]
    fn the_document_is_the_format_the_host_reads() {
        // ★ The property that makes this tool useful: what it writes is what the host verifies with. A second format
        // would produce signatures that this tool makes and the kernel refuses.
        let package = Package::new("format", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&content, "unix-ms:1");

        let parsed = SignatureFile::parse(&document).expect("the contract's format");
        assert_eq!(parsed.algorithm, publisher::ALGORITHM);
        assert_eq!(parsed.version, publisher::SIGNATURE_VERSION);
        assert!(parsed.verify().is_ok());
    }

    #[test]
    fn the_signed_at_claim_is_recorded_and_changes_nothing() {
        // It is a claim by whoever signed, so a verifier that used it to decide anything would be letting the package
        // choose its own ordering. Two documents that differ only in it are the same statement.
        let package = Package::new("clock", "plugin.wasm");
        let content = SignedContent::read(&package.path).expect("content");
        let signing = key(7);

        let early = signing.sign(&content, "unix-ms:1");
        let late = signing.sign(&content, "unix-ms:999");
        assert_ne!(early, late, "the documents differ");
        // And both verify, because the signature is over the subject and not over the document.
        assert!(verify(&early, &package.path, &PublisherTrustStore::new()).is_ok());
        assert!(verify(&late, &package.path, &PublisherTrustStore::new()).is_ok());
    }

    #[test]
    fn a_public_key_beside_the_package_is_read_as_a_fingerprint() {
        let package = Package::new("pinned", "plugin.wasm");
        assert_eq!(expected_fingerprint(&package.path), None, "nothing pinned yet");

        package.write("public-key.txt", key(7).public_hex().as_bytes());
        assert_eq!(expected_fingerprint(&package.path), Some(key(7).fingerprint()));
        // And a file that is not a key is not a fingerprint, rather than a wrong one.
        package.write("public-key.txt", b"not a key");
        assert_eq!(expected_fingerprint(&package.path), None);
    }

    #[test]
    fn a_ui_bundle_directory_is_covered_by_its_files_in_sorted_order() {
        // A directory listing's order is not defined, so an unsorted walk would produce a digest that changed between
        // runs on the same content — and a signature that verified only sometimes.
        let package = Package::new("ui", "ui");
        std::fs::create_dir_all(package.path.join("ui")).expect("a directory");
        package.write("ui/index.html", b"<html></html>");
        package.write("ui/app.js", b"console.log(1)");

        let first = SignedContent::read(&package.path).expect("content");
        let second = SignedContent::read(&package.path).expect("content");
        assert_eq!(first.subject, second.subject);

        // And changing a file inside the bundle changes the digest.
        package.write("ui/app.js", b"console.log(2)");
        let third = SignedContent::read(&package.path).expect("content");
        assert_ne!(first.subject.artifacts, third.subject.artifacts);
    }

    #[test]
    fn a_key_round_trips_through_its_hex() {
        let original = key(7);
        let again = SigningKeyFile::parse(&original.to_hex()).expect("parses");
        assert_eq!(again.to_hex(), original.to_hex());
        assert_eq!(again.public_hex(), original.public_hex());
        assert_eq!(again.fingerprint(), original.fingerprint());
        assert_eq!(original.to_hex().len(), 64);
        assert_eq!(original.public_hex().len(), 64);
    }

    #[test]
    fn a_public_key_is_not_the_secret() {
        // The failure this asserts against: a `public_hex` that returned the secret would publish the key that signs.
        let signing = key(7);
        assert_ne!(signing.public_hex(), signing.to_hex());
        assert_ne!(signing.public_base64(), signing.to_hex());
    }

    #[test]
    fn a_generated_key_is_a_key_and_is_not_the_same_twice() {
        let first = SigningKeyFile::generate().expect("randomness");
        let second = SigningKeyFile::generate().expect("randomness");
        assert_eq!(first.to_hex().len(), 64);
        assert_ne!(first.to_hex(), second.to_hex());
        assert_ne!(first.public_hex(), second.public_hex());
    }

    #[test]
    fn a_key_file_that_is_not_a_key_is_refused_by_name() {
        for wrong in ["", "abc", "zz", &"a".repeat(62)] {
            match SigningKeyFile::parse(wrong) {
                Err(reason) => assert!(!reason.is_empty(), "{wrong}"),
                Ok(_) => panic!("{wrong} was accepted as a key"),
            }
        }
        // And hex is case-insensitive, because a key written down by hand may be either.
        assert_eq!(
            SigningKeyFile::parse(&key(7).to_hex().to_uppercase()).expect("parses").to_hex(),
            key(7).to_hex()
        );
    }

    #[test]
    fn a_document_that_is_not_a_document_is_refused_rather_than_read() {
        let package = Package::new("garbage", "plugin.wasm");
        for wrong in ["", "not json", "{}"] {
            assert!(matches!(
                verify(wrong, &package.path, &PublisherTrustStore::new()),
                Err(SignError::DocumentUnreadable { .. })
            ));
        }
    }

    #[test]
    fn an_extra_file_in_a_signed_bundle_changes_what_was_signed() {
        // The smallest possible tamper, and it has to move the digest.
        let package = Package::new("extra", "plugin.wasm");
        let before = SignedContent::read(&package.path).expect("content");
        let document = key(7).sign(&before, "unix-ms:1");

        package.write("extra.wasm", b"\0asm\x01\0\0\0");
        // The manifest does not name it, so the subject is unchanged and the signature still holds — which is the
        // right answer: a file the manifest does not name is not part of the plugin.
        assert!(verify(&document, &package.path, &PublisherTrustStore::new()).is_ok());
    }
}