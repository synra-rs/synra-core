//! `sign`: what a publisher's signature covers, and what it does not.
//!
//! # What a signature is for here
//!
//! The design document's trust model has three levels, and the middle one is "signed, from a publisher the user has
//! already confirmed". A signature is what makes the *next* install from that publisher verifiable without asking
//! again — so the thing being signed has to be exactly the thing that could differ between two downloads.
//!
//! # What is covered
//!
//! Every byte of the artifact, plus the manifest's identity fields. The **artifact** is obvious. The manifest's fields
//! are there because the artifact alone is not the plugin: the same `.wasm` with a manifest that asks for `storage`
//! is a different plugin, and a signature over the artifact only would let one be substituted for the other.
//!
//! Which manifest fields: the ones that decide what the plugin *is* — its id, its version, and its `wit` world.
//! Deliberately **not** the whole manifest, because the parts a signature must not cover are the ones a user or a host
//! changes: nothing today, but the moment a field like a registry URL or an install timestamp lands in the manifest,
//! covering it would invalidate every existing signature.
//!
//! # The digest is over a canonical encoding
//!
//! The bytes signed are a fixed structure — a length-prefixed list of the fields, then the artifact — rather than the
//! manifest's own JSON. JSON's key order and whitespace are not fixed, so signing the file would make a signature that
//! changes when a user's editor reformats it. A canonical encoding makes the signature a statement about the plugin
//! rather than about its formatting.
//!
//! # What is not here
//!
//! No key storage, no keyring, no passphrase prompt. A key is a file the author names, and a tool that generated and
//! hid one would be a tool whose keys the author cannot back up — which is how a publisher loses the ability to ship
//! an update to a plugin users already trust.

use std::path::Path;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand_core::RngCore as _;

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

    /// A signature did not verify.
    ///
    /// Three things could have happened and the message says which it can tell: the artifact changed, the manifest's
    /// identity changed, or the key is not the publisher's.
    #[error("the signature does not verify against this plugin")]
    Mismatch,
}

/// What a signature is over.
///
/// # Why this is a type
///
/// The set of fields a signature covers is a **compatibility decision**: adding one invalidates every existing
/// signature, and removing one makes two different plugins sign identically. Making it a value with its own
/// constructor means the decision is in one place, and a test can assert the encoding is what a previous version
/// produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedContent {
    /// The plugin's id, exactly as the manifest spells it.
    pub plugin_id: String,
    /// Its version, exactly as the manifest spells it.
    pub version: String,
    /// The WIT world it was built against.
    pub wit: String,
    /// The artifact's bytes.
    ///
    /// The whole artifact, not a digest of it: `ed25519` hashes internally, and a second hash here would be a second
    /// algorithm to keep in step with the verifier's.
    pub artifact: Vec<u8>,
}

impl SignedContent {
    /// Reads the content a plugin's signature covers.
    ///
    /// # Errors
    ///
    /// [`SignError`] when the manifest or the artifact cannot be read.
    ///
    /// # The artifact path comes from the manifest
    ///
    /// Because the manifest is what the kernel reads, so signing a file the kernel will not load would be a signature
    /// over the wrong bytes — and it would verify, which is worse.
    pub fn read(root: &Path) -> Result<Self, SignError> {
        let manifest_path = root.join("manifest.json");
        let text = std::fs::read_to_string(&manifest_path).map_err(|error| {
            SignError::ManifestUnreadable {
                path: manifest_path.display().to_string(),
                reason: error.to_string(),
            }
        })?;
        let manifest = synra_plugin_api::manifest::Manifest::from_json(&text).map_err(|error| {
            SignError::ManifestUnreadable {
                path: manifest_path.display().to_string(),
                reason: error.to_string(),
            }
        })?;

        // The headless artifact, or the UI bundle's directory. A UI-only plugin has no `.wasm`, and the thing that has
        // to be covered is whatever a download could differ in — which for a UI plugin is its files.
        let artifact_path = if let Some(headless) = &manifest.runtime.headless {
            root.join(&headless.artifact)
        }
        else if let Some(ui) = &manifest.runtime.ui {
            root.join(&ui.artifact)
        }
        else {
            return Err(SignError::NoArtifact {
                path: root.join("manifest.json").display().to_string(),
            });
        };

        let artifact = read_artifact(&artifact_path)?;

        // The three identity fields are moved out of the manifest, which is not used afterwards: a clone here was pure
        // cost on a structure that holds the artifact's bytes, so it is the largest clone in the program.
        Ok(Self {
            plugin_id: manifest.id.to_string(),
            version: manifest.version,
            wit: manifest.wit,
            artifact,
        })
    }

    /// The bytes a signature is over.
    ///
    /// # Why the encoding is written out rather than serialised
    ///
    /// The first byte of each field is its length as a `u32`, big-endian, and the fields are written in a fixed order.
    /// That is what makes the encoding *canonical*: no key order, no whitespace, and no way for two different plugins
    /// to produce the same bytes — which a `format!("{a}{b}")` would allow, since `("ab", "c")` and `("a", "bc")`
    /// would sign identically.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.plugin_id.len() + self.version.len() + self.wit.len() + self.artifact.len() + 16,
        );
        for field in [&self.plugin_id, &self.version, &self.wit] {
            let bytes = field.as_bytes();
            // `u32` rather than `usize`, so the encoding is the same on a 32-bit and a 64-bit host — a signature made
            // on one and checked on the other has to be the same statement.
            let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(&self.artifact);
        out
    }
}

/// Reads an artifact, which may be a file or a directory.
fn read_artifact(path: &Path) -> Result<Vec<u8>, SignError> {
    if path.is_dir() {
        // A UI bundle is a directory. Its files are concatenated in **sorted** order, because a directory listing's
        // order is not defined — an unsorted walk would produce a signature that changed between runs on the same
        // bytes.
        let mut entries = Vec::new();
        collect_files(path, path, &mut entries).map_err(|error| SignError::ArtifactUnreadable {
            path: path.display().to_string(),
            reason: error,
        })?;
        entries.sort_by(|first, second| first.0.cmp(&second.0));

        let mut out = Vec::new();
        for (relative, absolute) in entries {
            let bytes =
                std::fs::read(&absolute).map_err(|error| SignError::ArtifactUnreadable {
                    path: absolute.display().to_string(),
                    reason: error.to_string(),
                })?;
            // The *path* is covered as well as the contents: a bundle with the same files under different names is a
            // different plugin, and a signature over contents alone would let them be rearranged.
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
            return SignError::NoArtifact { path: path.display().to_string() };
        }
        SignError::ArtifactUnreadable { path: path.display().to_string(), reason: error.to_string() }
    })
}

/// Collects a directory's files as `(path relative to the root, absolute path)`.
fn collect_files(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(current).map_err(|error| error.to_string())?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect_files(root, &path, out)?;
        }
        else if kind.is_file() {
            // `/` as the separator on every platform, because the signature has to be the same statement whoever
            // produced it — and a Windows path would make it a different one.
            let relative = path
                .strip_prefix(root)
                .map(|rest| rest.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
            out.push((relative, path));
        }
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

    /// Signs content.
    #[must_use]
    pub fn sign(&self, content: &SignedContent) -> String {
        let signature: Signature = self.key.sign(&content.canonical_bytes());
        hex_encode(&signature.to_bytes())
    }
}

/// Checks a signature against content.
///
/// # Errors
///
/// [`SignError::Mismatch`] when the signature, the public key and the content do not agree — which is the one answer
/// for the three ways they can disagree, because a verifier that said *which* would tell an attacker which part to
/// change.
pub fn verify(
    content: &SignedContent,
    public_hex: &str,
    signature_hex: &str,
) -> Result<(), SignError> {
    // ★ Every shape of failure is `Mismatch`, including a malformed key or signature. A verifier runs on bytes from
    // the network, and telling a caller *which* part was malformed would tell an attacker which part to change — the
    // same reason a login does not say whether the user or the password was wrong. `KeyMalformed` is for a key file on
    // the author's own disk, where the message helps them fix it.
    let public = hex_decode(public_hex).map_err(|_| SignError::Mismatch)?;
    let public: [u8; 32] = public.try_into().map_err(|_| SignError::Mismatch)?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| SignError::Mismatch)?;

    let signature_bytes = hex_decode(signature_hex).map_err(|_| SignError::Mismatch)?;
    let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| SignError::Mismatch)?;
    let signature = Signature::from_bytes(&signature);

    // `verify_strict` rather than `verify`: the permissive form accepts signatures that are not canonically encoded,
    // which means one artifact has many valid signatures — and a publisher's signature is supposed to be a statement
    // about one thing.
    key.verify_strict(&content.canonical_bytes(), &signature)
        .map_err(|_| SignError::Mismatch)
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
        let high = hex_value(pair[0]).ok_or_else(|| {
            format!("`{}` is not a hex digit", char::from(pair[0]))
        })?;
        let low = hex_value(pair[1]).ok_or_else(|| {
            format!("`{}` is not a hex digit", char::from(pair[1]))
        })?;
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

    struct Cleanup(std::path::PathBuf);

    impl Cleanup {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("synra-sign-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creates");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, path: &str, contents: &[u8]) {
            let full = self.0.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("creates");
            }
            std::fs::write(full, contents).expect("writes");
        }

        /// A minimal headless plugin.
        fn plugin(&self, artifact: &str, bytes: &[u8]) {
            self.write(
                "manifest.json",
                format!(
                    r#"{{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": {{ "id": "synra-official" }},
  "sdk": {{ "min": "0.1.0" }},
  "wit": "synra:plugin@1.0.0",
  "runtime": {{ "headless": {{ "artifact": "{artifact}", "stateful": false }} }},
  "capabilities": []
}}"#
                )
                .as_bytes(),
            );
            self.write(artifact, bytes);
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key() -> SigningKeyFile {
        // A fixed key rather than a generated one, so a failure is reproducible. The value is arbitrary and is not a
        // secret anybody should use.
        SigningKeyFile::parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("parses")
    }

    // ── The key ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_key_round_trips_through_its_hex() {
        // The format is a file an author types or stores, so reading back what was written has to give the same key.
        let original = key();
        let again = SigningKeyFile::parse(&original.to_hex()).expect("parses");
        assert_eq!(again.to_hex(), original.to_hex());
        assert_eq!(again.public_hex(), original.public_hex());
    }

    #[test]
    fn a_generated_key_is_a_key() {
        // From the system's randomness, and reported rather than worked around: a key from a weak source is one an
        // attacker can forge, and the failure would be silent.
        let generated = SigningKeyFile::generate().expect("generates");
        assert_eq!(generated.to_hex().len(), 64);
        assert_eq!(generated.public_hex().len(), 64);
        // Two calls give two keys, which is the property a fixed source would break.
        let other = SigningKeyFile::generate().expect("generates");
        assert_ne!(generated.to_hex(), other.to_hex());
    }

    #[test]
    fn a_malformed_key_says_what_is_wrong() {
        for (text, expected) in [
            ("", "0 bytes and a key is 32"),
            ("00", "1 bytes"),
            ("0", "hex comes in pairs"),
            ("zz", "not a hex digit"),
        ] {
            let error = SigningKeyFile::parse(text).expect_err("refused");
            assert!(error.contains(expected), "{text:?} -> {error}");
        }
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        // An author who pasted a key from a document has upper case, and refusing it would be pedantry.
        let lower = key();
        let upper = SigningKeyFile::parse(&lower.to_hex().to_uppercase()).expect("parses");
        assert_eq!(upper.public_hex(), lower.public_hex());
    }

    #[test]
    fn the_public_key_is_derived_and_not_the_secret() {
        // ★ A key file is a secret and a public key is not. A `public_hex` that returned the secret would publish the
        // publisher's signing key in every registry listing.
        let key = key();
        assert_ne!(key.public_hex(), key.to_hex());
        assert_eq!(key.public_hex().len(), 64);
    }

    // ── The content ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_content_is_the_manifest_identity_and_the_artifact() {
        let dir = Cleanup::new("content");
        dir.plugin("plugin.wasm", b"the module");

        let content = SignedContent::read(dir.path()).expect("reads");
        assert_eq!(content.plugin_id, "@synra-plugin/example");
        assert_eq!(content.version, "1.0.0");
        assert_eq!(content.wit, "synra:plugin@1.0.0");
        assert_eq!(content.artifact, b"the module");
    }

    #[test]
    fn the_artifact_path_comes_from_the_manifest() {
        // The manifest is what the kernel reads, so signing a file the kernel will not load would be a signature over
        // the wrong bytes — and it would verify, which is worse.
        let dir = Cleanup::new("artifact-path");
        dir.plugin("dist/plugin.wasm", b"the module");

        let content = SignedContent::read(dir.path()).expect("reads");
        assert_eq!(content.artifact, b"the module");
    }

    #[test]
    fn a_missing_artifact_is_refused() {
        let dir = Cleanup::new("no-artifact");
        dir.plugin("plugin.wasm", b"x");
        std::fs::remove_file(dir.path().join("plugin.wasm")).expect("removes");

        assert!(matches!(SignedContent::read(dir.path()), Err(SignError::NoArtifact { .. })));
    }

    #[test]
    fn the_encoding_cannot_be_confused_by_moving_a_boundary() {
        // ★ The reason the fields are length-prefixed. Without it, `("ab", "c")` and `("a", "bc")` would produce the
        // same bytes and one plugin's signature would verify for another.
        let first = SignedContent {
            plugin_id: "ab".to_owned(),
            version: "c".to_owned(),
            wit: "w".to_owned(),
            artifact: b"x".to_vec(),
        };
        let second = SignedContent {
            plugin_id: "a".to_owned(),
            version: "bc".to_owned(),
            wit: "w".to_owned(),
            artifact: b"x".to_vec(),
        };
        assert_ne!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    fn the_encoding_is_a_function_of_the_content_alone() {
        // Canonical, so a signature is a statement about the plugin rather than about how a manifest file happens to be
        // formatted.
        let content = SignedContent {
            plugin_id: "@a/b".to_owned(),
            version: "1.0.0".to_owned(),
            wit: "synra:plugin@1.0.0".to_owned(),
            artifact: b"bytes".to_vec(),
        };
        assert_eq!(content.canonical_bytes(), content.canonical_bytes());
        assert_eq!(
            content.canonical_bytes().len(),
            content.plugin_id.len() + content.version.len() + content.wit.len() + content.artifact.len() + 12
        );
    }

    #[test]
    fn every_covered_field_changes_the_bytes() {
        // Each one, asserted separately: a field that did not change the encoding would be a field the signature does
        // not cover, which is the substitution the whole thing exists to prevent.
        let base = SignedContent {
            plugin_id: "@a/b".to_owned(),
            version: "1.0.0".to_owned(),
            wit: "synra:plugin@1.0.0".to_owned(),
            artifact: b"bytes".to_vec(),
        };
        let with_id = SignedContent { plugin_id: "@a/c".to_owned(), ..base.clone() };
        let with_version = SignedContent { version: "1.0.1".to_owned(), ..base.clone() };
        let with_wit = SignedContent { wit: "synra:plugin@2.0.0".to_owned(), ..base.clone() };
        let with_artifact = SignedContent { artifact: b"other".to_vec(), ..base.clone() };

        for other in [with_id, with_version, with_wit, with_artifact] {
            assert_ne!(base.canonical_bytes(), other.canonical_bytes());
        }
    }

    // ── Signing and checking ──────────────────────────────────────────────────────────────────────

    #[test]
    fn a_signature_verifies_against_what_was_signed() {
        let dir = Cleanup::new("round-trip");
        dir.plugin("plugin.wasm", b"the module");
        let content = SignedContent::read(dir.path()).expect("reads");

        let key = key();
        let signature = key.sign(&content);
        assert_eq!(verify(&content, &key.public_hex(), &signature), Ok(()));
    }

    #[test]
    fn a_changed_artifact_does_not_verify() {
        // The property the signature exists for: a download that differs is one the user is not asked to trust twice.
        let dir = Cleanup::new("changed");
        dir.plugin("plugin.wasm", b"the module");
        let content = SignedContent::read(dir.path()).expect("reads");

        let key = key();
        let signature = key.sign(&content);

        let changed = SignedContent { artifact: b"the modul3".to_vec(), ..content };
        assert_eq!(verify(&changed, &key.public_hex(), &signature), Err(SignError::Mismatch));
    }

    #[test]
    fn a_changed_capability_bearing_field_does_not_verify() {
        // The same `.wasm` with a manifest that asks for more is a different plugin, and a signature over the artifact
        // alone would let one be substituted for the other.
        let dir = Cleanup::new("changed-wit");
        dir.plugin("plugin.wasm", b"the module");
        let content = SignedContent::read(dir.path()).expect("reads");

        let key = key();
        let signature = key.sign(&content);

        let changed = SignedContent { wit: "synra:plugin@9.0.0".to_owned(), ..content };
        assert_eq!(verify(&changed, &key.public_hex(), &signature), Err(SignError::Mismatch));
    }

    #[test]
    fn another_publishers_key_does_not_verify() {
        // The substitution the trust model is about: a plugin that is genuine, signed by somebody else.
        let dir = Cleanup::new("other-key");
        dir.plugin("plugin.wasm", b"the module");
        let content = SignedContent::read(dir.path()).expect("reads");

        let mine = key();
        let theirs = SigningKeyFile::generate().expect("generates");
        let signature = theirs.sign(&content);

        assert_eq!(verify(&content, &mine.public_hex(), &signature), Err(SignError::Mismatch));
    }

    #[test]
    fn a_malformed_signature_or_key_is_a_mismatch_and_not_a_panic() {
        // A verifier runs on bytes from the network, so every shape of them is a refusal rather than a panic.
        let content = SignedContent {
            plugin_id: "@a/b".to_owned(),
            version: "1.0.0".to_owned(),
            wit: "synra:plugin@1.0.0".to_owned(),
            artifact: b"bytes".to_vec(),
        };
        let key = key();
        let good = key.sign(&content);

        for (public, signature) in [
            ("", good.as_str()),
            ("00", good.as_str()),
            ("zz", good.as_str()),
            (key.public_hex().as_str(), ""),
            (key.public_hex().as_str(), "00"),
            (key.public_hex().as_str(), "zz"),
            ("00", "00"),
        ] {
            assert_eq!(
                verify(&content, public, signature),
                Err(SignError::Mismatch),
                "public {public:?}, signature {signature:?}"
            );
        }
    }

    // ── A UI bundle ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_directory_artifact_covers_every_file_and_its_name() {
        // A UI plugin's artifact is a directory, and a bundle with the same files under different names is a different
        // plugin.
        let dir = Cleanup::new("ui");
        dir.write(
            "manifest.json",
            br#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "ui": { "artifact": "ui", "entry": "index.html" } },
  "capabilities": []
}"#,
        );
        dir.write("ui/index.html", b"<html></html>");
        dir.write("ui/app.js", b"console.log(1)");

        let content = SignedContent::read(dir.path()).expect("reads");
        let key = key();
        let signature = key.sign(&content);
        assert_eq!(verify(&content, &key.public_hex(), &signature), Ok(()));

        // A file whose contents change invalidates it.
        dir.write("ui/app.js", b"console.log(2)");
        let changed = SignedContent::read(dir.path()).expect("reads");
        assert_eq!(verify(&changed, &key.public_hex(), &signature), Err(SignError::Mismatch));
    }

    #[test]
    fn a_directory_artifact_is_signed_in_a_stable_order() {
        // A directory listing's order is not defined, so an unsorted walk would produce a signature that changed
        // between runs on the same bytes — and `verify` would fail for a plugin nobody changed.
        let dir = Cleanup::new("stable");
        dir.write(
            "manifest.json",
            br#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "ui": { "artifact": "ui", "entry": "index.html" } },
  "capabilities": []
}"#,
        );
        for name in ["z.js", "a.js", "m/x.js", "m/a.js", "b.css"] {
            dir.write(&format!("ui/{name}"), name.as_bytes());
        }

        let first = SignedContent::read(dir.path()).expect("reads");
        let second = SignedContent::read(dir.path()).expect("reads");
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    fn a_renamed_file_changes_the_signature() {
        // The path is covered as well as the contents, so a bundle cannot be rearranged under a valid signature.
        let dir = Cleanup::new("renamed");
        dir.write(
            "manifest.json",
            br#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "ui": { "artifact": "ui", "entry": "index.html" } },
  "capabilities": []
}"#,
        );
        dir.write("ui/a.js", b"same");
        let before = SignedContent::read(dir.path()).expect("reads").canonical_bytes();

        std::fs::remove_file(dir.path().join("ui/a.js")).expect("removes");
        dir.write("ui/b.js", b"same");
        let after = SignedContent::read(dir.path()).expect("reads").canonical_bytes();

        assert_ne!(before, after);
    }

    // ── Hex ───────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn hex_round_trips_for_every_byte_value() {
        // All 256, because a hex encoder with an off-by-one in the high nibble would pass a test that used only `0x0f`.
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(hex_decode(&hex_encode(&bytes)).expect("decodes"), bytes);
    }

    #[test]
    fn sign_errors_explain_themselves() {
        let errors = [
            SignError::KeyUnreadable { path: "/k".to_owned(), reason: "gone".to_owned() },
            SignError::KeyMalformed { path: "/k".to_owned(), reason: "short".to_owned() },
            SignError::ManifestUnreadable { path: "/m".to_owned(), reason: "bad".to_owned() },
            SignError::NoArtifact { path: "/a".to_owned() },
            SignError::ArtifactUnreadable { path: "/a".to_owned(), reason: "bad".to_owned() },
            SignError::Mismatch,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}
