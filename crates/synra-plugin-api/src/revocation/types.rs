use serde::{Deserialize, Serialize};

use crate::publisher::Fingerprint;

/// Why a revocation list could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// The document is not JSON, or not this shape.
    #[error("the revocation list is not readable: {detail}")]
    Malformed {
        /// What the parser said.
        detail: String,
    },
    /// An entry names neither a plugin version nor a publisher.
    #[error("entry {index} names neither a plugin version nor a publisher")]
    EmptyEntry {
        /// Which entry, counting from zero, as it appears in the document.
        index: usize,
    },
    /// An entry names a plugin but no versions.
    #[error("entry {index} names `{plugin}` and no versions")]
    NoVersions {
        /// The plugin it names.
        plugin: String,
        /// Which entry.
        index: usize,
    },
    /// A fingerprint that is not one.
    #[error("entry {index} has a fingerprint that is not one: {detail}")]
    BadFingerprint {
        /// Which entry.
        index: usize,
        /// What the parser said.
        detail: String,
    },
}

/// One line of the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RawEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pubkey_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) at: Option<String>,
}

/// The document itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RawList {
    pub(super) revoked: Vec<RawEntry>,
}

pub(super) fn reason_of(reason: &Option<String>) -> String {
    reason
        .clone()
        .unwrap_or_else(|| "revoked with no reason given".to_owned())
}

pub(super) fn parse_fingerprint(text: &str, index: usize) -> Result<Fingerprint, RevocationError> {
    Fingerprint::parse(text).map_err(|error| RevocationError::BadFingerprint {
        index,
        detail: error.to_string(),
    })
}
