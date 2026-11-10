//! Signing key file handling and signature creation.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::RngCore as _;
use synra_plugin_api::publisher::{self, Fingerprint};

use super::{SignError, SignedContent};

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
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
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
pub(super) fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
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


