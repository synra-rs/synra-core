//! SRI parsing and downloaded tarball verification.

use base64::Engine;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::FetchFailure;

/// Compares two version strings by their numeric parts.
///
/// Not a semver implementation, and deliberately: the only question this answers is "which of these two is newer",
/// for a registry that sent no `latest` tag. A pre-release is treated as *older* than its release, which is the one
/// semantic rule that matters for picking a default and the one a plain comparison gets wrong.
#[must_use]
pub fn compare_versions(first: &str, second: &str) -> core::cmp::Ordering {
    let parts = |version: &str| -> (Vec<u64>, bool) {
        let (core, pre) = version.split_once('-').map_or((version, ""), |(core, pre)| (core, pre));
        let numbers = core
            .split(['.', '+'])
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect();
        (numbers, !pre.is_empty())
    };
    let (left, left_pre) = parts(first);
    let (right, right_pre) = parts(second);
    match left.cmp(&right) {
        core::cmp::Ordering::Equal => {
            // A release is newer than its own pre-releases.
            match (left_pre, right_pre) {
                (true, false) => core::cmp::Ordering::Less,
                (false, true) => core::cmp::Ordering::Greater,
                _ => core::cmp::Ordering::Equal,
            }
        }
        other => other,
    }
}

/// A digest a downloaded artifact must hash to.
///
/// # The algorithm is named in the digest
///
/// An SRI string is `algorithm-base64`, and the algorithm is part of it. A verifier that had to be told which
/// algorithm to use would be a verifier that could be told the wrong one — and the failure mode of "check it with
/// MD5" is a check that passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    /// The algorithm, as the string spells it: `sha256`, `sha384` or `sha512`.
    pub algorithm: String,
    /// The base64 digest, without its padding — which is how SRI spells one.
    pub digest: String,
}

impl Integrity {
    /// Parses an SRI string.
    ///
    /// # Errors
    ///
    /// [`FetchFailure::Malformed`] when the string is not `algorithm-base64`, names an algorithm this build cannot
    /// compute, or carries a digest of the wrong length for it. Each is refused rather than ignored: an integrity
    /// string nobody can check is one that reads as "no integrity", and that is the answer that lets a substituted
    /// tarball through.
    pub fn parse(registry: &str, text: &str) -> Result<Self, FetchFailure> {
        let malformed = |reason: String| FetchFailure::Malformed { registry: registry.to_owned(), reason };
        let (algorithm, digest) = text
            .split_once('-')
            .ok_or_else(|| malformed(format!("`{text}` is not an SRI digest")))?;
        let algorithm = algorithm.to_lowercase();
        let expected = match algorithm.as_str() {
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            other => {
                return Err(malformed(format!("`{other}` is not a digest this build computes")));
            }
        };
        if digest.is_empty() {
            return Err(malformed("the digest is empty".to_owned()));
        }
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(digest.trim_end_matches('='))
            .map_err(|error| malformed(format!("the digest is not base64: {error}")))?;
        if decoded.len() != expected {
            return Err(malformed(format!(
                "a {algorithm} digest is {expected} bytes and this one is {}",
                decoded.len()
            )));
        }
        Ok(Self { algorithm, digest: digest.trim_end_matches('=').to_owned() })
    }

    /// Whether some bytes hash to this digest.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        let computed = match self.algorithm.as_str() {
            "sha256" => Sha256::digest(bytes).to_vec(),
            "sha384" => Sha384::digest(bytes).to_vec(),
            "sha512" => Sha512::digest(bytes).to_vec(),
            _ => return false,
        };
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(computed);
        // Compared as encoded text rather than as bytes, so a digest with different padding that a mirror sent is the
        // same digest.
        encoded.trim_end_matches('=') == self.digest
    }

    /// The digest as it is written.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}-{}", self.algorithm, self.digest)
    }
}

/// Checks a downloaded tarball against what the registry declared.
///
/// # Errors
///
/// [`FetchFailure::IntegrityMismatch`], which is the failure that must never fall through to another mirror, and
/// [`FetchFailure::Malformed`] when the registry declared an integrity nobody can check.
pub fn check_integrity(registry: &str, declared: &str, bytes: &[u8]) -> Result<Integrity, FetchFailure> {
    let integrity = Integrity::parse(registry, declared)?;
    if !integrity.matches(bytes) {
        return Err(FetchFailure::IntegrityMismatch {
            registry: registry.to_owned(),
            declared: integrity.as_str(),
        });
    }
    Ok(integrity)
}


