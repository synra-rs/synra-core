//! The signature on a published plugin, and the decisions a device makes about publishers.
//!
//! # What a signature is *for*, and what it is not
//!
//! It proves that whoever holds a private key produced this combination of manifest and artifacts. It does **not**
//! say the plugin is safe, and it does not say the publisher is who their name claims: those are judgements a user
//! makes, and this module's job is to give them the two facts the judgement needs — *which* key signed this, and
//! whether this device has seen that key before for that name.
//!
//! That second fact is the whole reason [`PublisherTrustStore`] exists. A name is free; a key is not. So a plugin
//! signed by `imba97` is only as good as the answer to "is this the same key the last `imba97` plugin had?", and a
//! store that answered "yes, the id matches" without comparing the key would be the vulnerability the design document
//! names: an id is forgeable, a key is not.
//!
//! # Why the signed bytes are canonical and hand-built
//!
//! Because a signature is over **bytes**, and `serde_json::to_string` on a struct is a promise about field order that
//! a later refactor can break silently. A signature that stopped verifying after an unrelated change to a struct is
//! indistinguishable from a tampered package, and every user would be told their plugin had been altered. So the
//! payload is built by hand, in a fixed order, with the two things that could vary — map iteration and whitespace —
//! absent by construction.
//!
//! # What is deliberately not here
//!
//! Key rotation. The design document puts it in v2 and says the first version supports one key per publisher, which
//! is also what makes the rule below so blunt: an id whose key changed is **untrusted**, not "possibly rotated". A
//! host that guessed would be a host that could be made to accept a different key by whoever controlled the id.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::manifest::{Manifest, Publisher};

/// The only signing algorithm this version knows.
pub const ALGORITHM: &str = "ed25519";

/// The version of the signature document.
pub const SIGNATURE_VERSION: u32 = 1;

/// The file a published package carries its signature in.
pub const SIGNATURE_FILE: &str = "signature.json";

/// Why a signature document could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The document is not JSON, or does not have the shape this version requires.
    #[error("the signature could not be read: {detail}")]
    Unreadable {
        /// What the parser said.
        detail: String,
    },

    /// The document declares a version this build does not know.
    ///
    /// Named separately from [`Self::Unreadable`] because the caller's next step differs: an older host told "upgrade
    /// the application" is being told something it can act on.
    #[error("the signature is version {found} and this build understands {known}")]
    Version {
        /// What the document declares.
        found: u32,
        /// What this build knows.
        known: u32,
    },

    /// The algorithm is not one this build can check.
    ///
    /// ★ Refused rather than skipped. A verifier that ignored an algorithm it did not know would report "no signature
    /// to check" for a package that has one, which is the answer that lets a package through.
    #[error("the signature uses {found}, which this build cannot check")]
    Algorithm {
        /// What the document declares.
        found: String,
    },

    /// The public key is not a valid ed25519 key.
    #[error("the publisher's public key is not one: {detail}")]
    PublicKey {
        /// Why.
        detail: String,
    },

    /// The signature is not a valid ed25519 signature.
    #[error("the signature is not one: {detail}")]
    Signature {
        /// Why.
        detail: String,
    },
}

/// What a publisher signed.
///
/// # Why the artifacts are a map and not a list
///
/// Because the signed bytes are built from it, and a list has an order — so two packages with the same files in a
/// different order would have different signed bytes, and a repackaging that changed nothing would invalidate a
/// signature. A `BTreeMap` also gives the fixed iteration order the canonical form needs, which is what makes "sort
/// the keys" a property of the type rather than a step somebody has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningSubject {
    /// The digest of the manifest, as an SRI string.
    pub manifest: String,
    /// Each artifact's digest, by file name.
    pub artifacts: BTreeMap<String, String>,
}

impl SigningSubject {
    /// The bytes a signature is over.
    ///
    /// # The shape, and why every choice in it matters
    ///
    /// * **No whitespace.** A pretty-printed form would make the payload depend on a formatting option.
    /// * **A fixed key order.** Not the order of the map — `BTreeMap` sorts, so it is the order of the alphabet.
    /// * **Escaping by the JSON rules, not by `Display`.** A file name with a quote in it would otherwise produce
    ///   bytes that two implementations read differently, and one of them would verify a signature over something
    ///   other than what it checked.
    /// * **The signature itself is absent.** It cannot sign itself.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::with_capacity(128);
        out.push_str("{\"manifest\":");
        push_json_string(&mut out, &self.manifest);
        out.push_str(",\"artifacts\":{");
        for (index, (name, digest)) in self.artifacts.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            push_json_string(&mut out, name);
            out.push(':');
            push_json_string(&mut out, digest);
        }
        out.push_str("}}");
        out.into_bytes()
    }

    /// Whether every artifact the manifest names is covered by the signature.
    ///
    /// # Why this is checked at all
    ///
    /// Because a signature over a *subset* of a package is a signature over a different package. A plugin whose
    /// manifest names `plugin.wasm` and `ui.zip`, signed over only `plugin.wasm`, is one where the interface half can
    /// be replaced by anybody — and the signature would still verify.
    #[must_use]
    pub fn covers(&self, manifest: &Manifest) -> Vec<String> {
        let mut missing = Vec::new();
        if let Some(headless) = &manifest.runtime.headless
            && !self.artifacts.contains_key(&headless.artifact)
        {
            missing.push(headless.artifact.clone());
        }
        if let Some(ui) = &manifest.runtime.ui
            && !self.artifacts.contains_key(&ui.artifact)
        {
            missing.push(ui.artifact.clone());
        }
        missing.sort();
        missing
    }
}

/// Writes a string as a JSON string literal, following the JSON rules.
///
/// The escapes are the ones the specification requires. Everything else is passed through as-is, which is what makes
/// this the *same* bytes a conforming implementation produces rather than a locale- or platform-dependent rendering.
fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control < '\u{20}' => {
                let _ = std::fmt::Write::write_fmt(out, format_args!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The signature document, as it is published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignatureFile {
    /// Which version of this document it is.
    pub version: u32,
    /// Who signed it, with the key they signed with.
    pub publisher: Publisher,
    /// The algorithm, so a document from a future version is refused by name rather than misread.
    pub algorithm: String,
    /// When it was signed, as the publisher's own timestamp.
    ///
    /// Recorded and **not trusted**: it is a claim by whoever signed, and a verifier that used it to decide anything
    /// — "this is newer, so it wins" — would be letting the package choose its own ordering.
    pub signed_at: String,
    /// The public key, base64.
    pub pubkey: String,
    /// What was signed.
    pub subject: SigningSubject,
    /// The signature over [`SigningSubject::canonical_bytes`], base64.
    pub signature: String,
}

impl SignatureFile {
    /// Parses a document.
    ///
    /// # Errors
    ///
    /// [`SignatureError::Unreadable`] for a document that is not JSON or does not have this shape, and
    /// [`SignatureError::Version`] or [`SignatureError::Algorithm`] for one this build cannot check.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        let document: Self = serde_json::from_str(text)
            .map_err(|error| SignatureError::Unreadable { detail: error.to_string() })?;
        if document.version != SIGNATURE_VERSION {
            return Err(SignatureError::Version {
                found: document.version,
                known: SIGNATURE_VERSION,
            });
        }
        if document.algorithm != ALGORITHM {
            return Err(SignatureError::Algorithm { found: document.algorithm });
        }
        Ok(document)
    }

    /// The publisher's key.
    ///
    /// # Errors
    ///
    /// [`SignatureError::PublicKey`] when the base64 or the key itself is not valid.
    pub fn verifying_key(&self) -> Result<VerifyingKey, SignatureError> {
        let bytes = BASE64
            .decode(self.pubkey.as_bytes())
            .map_err(|error| SignatureError::PublicKey { detail: error.to_string() })?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SignatureError::PublicKey { detail: "a key is 32 bytes".to_owned() })?;
        VerifyingKey::from_bytes(&array)
            .map_err(|error| SignatureError::PublicKey { detail: error.to_string() })
    }

    /// Checks the signature over the subject.
    ///
    /// # Errors
    ///
    /// [`SignatureError::PublicKey`] or [`SignatureError::Signature`] when either is malformed. A signature that is
    /// well-formed and **wrong** is not an error: it is
    /// [`VerifyOutcome::BadSignature`], because a caller has a different next step for each — one is a broken
    /// package, the other is a tampered one.
    pub fn verify(&self) -> Result<VerifyOutcome, SignatureError> {
        let key = self.verifying_key()?;
        let signature_bytes = BASE64
            .decode(self.signature.as_bytes())
            .map_err(|error| SignatureError::Signature { detail: error.to_string() })?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| SignatureError::Signature { detail: error.to_string() })?;

        Ok(match key.verify(&self.subject.canonical_bytes(), &signature) {
            Ok(()) => VerifyOutcome::Good { fingerprint: Fingerprint::of(&key) },
            Err(_) => VerifyOutcome::BadSignature,
        })
    }
}

/// A short, comparable rendering of a public key.
///
/// # Why the user is shown this and not the key
///
/// Because the decision is "is this the same key as last time?", and a person compares sixteen characters. The full
/// key is 32 bytes of base64, which nobody reads and everybody scrolls past — and a fingerprint that is not read is
/// not a check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Derives a fingerprint from a key.
    ///
    /// The first sixteen bytes of a SHA-256 over the key, as uppercase hex in groups of four. The hash is not there
    /// for secrecy — a public key is public — but for *length*: a comparison a person makes has to fit on a line.
    #[must_use]
    pub fn of(key: &VerifyingKey) -> Self {
        let digest = Sha256::digest(key.as_bytes());
        let hex: String = digest.iter().take(8).fold(String::with_capacity(16), |mut text, byte| {
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!("{byte:02X}"));
            text
        });
        let grouped = hex
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<String>>()
            .join(" ");
        Self(grouped)
    }

    /// Parses a fingerprint as it was written down.
    ///
    /// Lenient about case and separators, because a fingerprint a user typed came from a screen that grouped it.
    ///
    /// # Errors
    ///
    /// [`SignatureError::PublicKey`] when it is not thirty-two hex digits once the separators are removed.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        let stripped: String = text.chars().filter(|character| character.is_ascii_hexdigit()).collect();
        if stripped.len() != 16 {
            return Err(SignatureError::PublicKey {
                detail: format!("a fingerprint is 16 hex digits and this is {}", stripped.len()),
            });
        }
        let upper = stripped.to_uppercase();
        let grouped = upper
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<String>>()
            .join(" ");
        Ok(Self(grouped))
    }

    /// The fingerprint as it is shown.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What a signature check produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyOutcome {
    /// The signature is valid. This says nothing yet about whether the publisher is trusted.
    Good {
        /// Which key signed it.
        fingerprint: Fingerprint,
    },
    /// The signature is well-formed and wrong.
    ///
    /// ★ The one outcome that is never a warning. Either the package was altered after signing or it was signed over
    /// something else, and there is no third explanation — so a caller that treats this as "probably fine" has
    /// removed the only check there is.
    BadSignature,
}

/// How much a device trusts a plugin's publisher.
///
/// Not `Copy`: the refusal arm holds a sentence, and a type that is cheap to pass around by value is one that gets
/// compared and logged without anybody thinking about whether the reason matters. It does — it is what a user is
/// shown when a package is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginTrust {
    /// Signed by a publisher this device has trusted before, with the key it trusted.
    TrustedPublisher,
    /// The signature is valid and this is the first plugin from this publisher.
    ///
    /// The state a prompt is drawn for: the fingerprint is what a user compares, and "trust this publisher" writes
    /// the key into the store. **Not** the same as trusted, and a caller that treated it as such would be asking for
    /// consent it never obtained.
    UnknownPublisher,
    /// Unsigned.
    ///
    /// Allowed, because a plugin a user built themselves has no publisher — but it is a distinct answer, because a
    /// caller that showed an unsigned plugin the same way as a signed one would be showing a check that did not
    /// happen.
    Unsigned,
    /// Signed by a key this device refuses.
    Untrusted {
        /// Why.
        why: Untrusted,
    },
}

impl PluginTrust {
    /// Whether a plugin with this trust may be activated without a new decision.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::TrustedPublisher)
    }

    /// Whether this is a reason to refuse an installation outright.
    ///
    /// A revoked key or a changed one is not something a user can consent past: the first is a decision the project
    /// has already made, and the second is the exact attack the store exists to catch. An unknown publisher is not a
    /// refusal — it is a question.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        matches!(self, Self::Untrusted { .. })
    }

    /// A name, for a log line and a state column.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TrustedPublisher => "trusted-publisher",
            Self::UnknownPublisher => "unknown-publisher",
            Self::Unsigned => "unsigned",
            Self::Untrusted { .. } => "untrusted",
        }
    }
}

/// Why a device refuses a publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Untrusted {
    /// This key is on the revocation list.
    ///
    /// A decision already made, by the project or by the user, and not one an installation may talk its way past.
    Revoked {
        /// Why it was revoked.
        reason: String,
    },
    /// This publisher's id is known with a **different** key.
    ///
    /// ★ The rule the store exists for. An id is free; a key is not. Either the id is being impersonated or a key was
    /// rotated without telling anyone — and the first version supports one key per publisher, so both answers are
    /// "do not install".
    KeyChanged {
        /// The key this device trusted.
        known: Fingerprint,
        /// The key that signed this package.
        presented: Fingerprint,
    },
}

impl std::fmt::Display for Untrusted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Revoked { reason } => write!(formatter, "the publisher's key was revoked: {reason}"),
            Self::KeyChanged { known, presented } => write!(
                formatter,
                "this publisher is known with key {known}, and this package is signed with {presented}"
            ),
        }
    }
}

/// What a signature check concluded, before any decision about the publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureCheck {
    /// A valid signature by this key.
    Good {
        /// The publisher's id, as the document declares it.
        publisher_id: String,
        /// The fingerprint, for a prompt.
        fingerprint: Fingerprint,
        /// What was signed.
        subject: SigningSubject,
    },
    /// A well-formed signature that does not verify.
    Bad,
    /// No signature at all.
    None,
}

/// Checks a package's signature against its manifest.
///
/// # The order the checks happen in, and why
///
/// The signature is verified **before** anything is concluded about the publisher, and the artifacts the manifest
/// names are checked **before** either. A package whose signature does not cover what it ships is one where
/// verifying the signature first would produce a reassuring answer about the wrong bytes.
///
/// # Errors
///
/// [`SignatureError`] for a document that cannot be read at all.
pub fn check(
    signature: Option<&str>,
    manifest: &Manifest,
    artifact_digests: &BTreeMap<String, String>,
) -> Result<SignatureCheck, SignatureError> {
    let Some(text) = signature else {
        return Ok(SignatureCheck::None);
    };
    let document = SignatureFile::parse(text)?;

    // The artifacts the manifest names have to be the ones that were signed. A digest map that disagrees with the
    // signature is a package assembled from parts, which is the thing a signature is supposed to make impossible.
    if !document.subject.covers(manifest).is_empty() {
        return Ok(SignatureCheck::Bad);
    }
    for (name, digest) in artifact_digests {
        match document.subject.artifacts.get(name) {
            Some(signed) if signed == digest => {}
            _ => return Ok(SignatureCheck::Bad),
        }
    }

    match document.verify()? {
        VerifyOutcome::BadSignature => Ok(SignatureCheck::Bad),
        VerifyOutcome::Good { fingerprint } => Ok(SignatureCheck::Good {
            publisher_id: document.publisher.id,
            fingerprint,
            subject: document.subject,
        }),
    }
}

/// A device's decisions about publishers, and the list it refuses.
///
/// # Why the trusted value is a fingerprint and not a publisher record
///
/// Because the only question worth remembering the answer to is "is this the same key?". A record holding a name and
/// a URL would be a record that grows fields nothing checks, and a trust decision that depended on a name is a
/// decision an impostor can satisfy.
#[derive(Debug, Clone, Default)]
pub struct PublisherTrustStore {
    trusted: HashMap<String, Fingerprint>,
    revoked: HashSet<Fingerprint>,
    revocation_reasons: HashMap<Fingerprint, String>,
}

impl PublisherTrustStore {
    /// A store that trusts nobody and refuses nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a user trusts this publisher's key.
    ///
    /// Replaces an earlier key for the same id, which is what "the user chose to trust the new key" means: the store
    /// records decisions, and refusing to record one would leave a user unable to recover from a legitimate rotation
    /// they were told about out of band.
    pub fn trust(&mut self, publisher_id: impl Into<String>, fingerprint: Fingerprint) {
        let _ = self.trusted.insert(publisher_id.into(), fingerprint);
    }

    /// Forgets a publisher, which is what "untrust" does.
    ///
    /// # Returns
    ///
    /// Whether anything was forgotten.
    pub fn forget(&mut self, publisher_id: &str) -> bool {
        self.trusted.remove(publisher_id).is_some()
    }

    /// Revokes a key.
    pub fn revoke(&mut self, fingerprint: Fingerprint, reason: impl Into<String>) {
        let _ = self.revoked.insert(fingerprint.clone());
        let _ = self.revocation_reasons.insert(fingerprint, reason.into());
    }

    /// Whether a key is revoked.
    #[must_use]
    pub fn is_revoked(&self, fingerprint: &Fingerprint) -> bool {
        self.revoked.contains(fingerprint)
    }

    /// The key this device trusts for a publisher, if it trusts one.
    #[must_use]
    pub fn trusted_key(&self, publisher_id: &str) -> Option<&Fingerprint> {
        self.trusted.get(publisher_id)
    }

    /// How many publishers are trusted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.trusted.len()
    }

    /// Whether nothing is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    /// What to make of a signed package by this publisher.
    ///
    /// # The order, and it is the whole security argument
    ///
    /// 1. A **revoked key** is refused whatever else is true, including by a publisher this device trusts: a
    ///    revocation is a decision made *after* a trust decision, and letting trust win would make revocation
    ///    impossible to apply.
    /// 2. A publisher with a **different key** is refused. This is the impersonation case, and it is checked before
    ///    "is it trusted" because the answer to that question is the one being asked.
    /// 3. A publisher with **this key** is trusted.
    /// 4. A publisher **nobody has seen** is a question, not an answer.
    #[must_use]
    pub fn classify(&self, publisher_id: &str, fingerprint: &Fingerprint) -> PluginTrust {
        if let Some(reason) = self.revocation_reasons.get(fingerprint) {
            return PluginTrust::Untrusted { why: Untrusted::Revoked { reason: reason.clone() } };
        }
        match self.trusted.get(publisher_id) {
            Some(known) if known == fingerprint => PluginTrust::TrustedPublisher,
            Some(known) => PluginTrust::Untrusted {
                why: Untrusted::KeyChanged { known: known.clone(), presented: fingerprint.clone() },
            },
            None => PluginTrust::UnknownPublisher,
        }
    }

    /// What to make of a check that produced no signature.
    #[must_use]
    pub const fn classify_unsigned() -> PluginTrust {
        PluginTrust::Unsigned
    }
}

#[cfg(test)]
#[path = "publisher_tests.rs"]
mod tests;
