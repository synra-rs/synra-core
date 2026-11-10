//! Errors raised while reading or checking publisher signatures.

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


