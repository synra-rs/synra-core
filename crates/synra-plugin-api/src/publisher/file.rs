//! Published signature documents and key fingerprints.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::manifest::Publisher;
use super::subject::SigningSubject;
use super::{ALGORITHM, SIGNATURE_VERSION};
use super::errors::SignatureError;

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


