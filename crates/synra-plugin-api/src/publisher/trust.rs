//! Publisher trust decisions and signature checks.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::errors::SignatureError;
use super::file::{Fingerprint, VerifyOutcome, SignatureFile};
use super::subject::SigningSubject;
use super::super::manifest::Manifest;

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


