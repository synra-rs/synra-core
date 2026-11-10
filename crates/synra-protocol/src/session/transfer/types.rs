use core::fmt;

use serde::{Deserialize, Serialize};
use crate::ids::{PluginId, SessionId, TransferId};

/// The kind of a transfer, so the receiver knows where the bytes go before they arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TransferKind {
    /// A plugin's artifact, being synchronised for installation.
    PluginBundle,
    /// A file a user or a plugin is sending.
    Attachment,
}

/// The digest algorithms this protocol accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256, the only one currently accepted.
    Sha256,
}

impl DigestAlgorithm {
    /// The prefix used in the wire form.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }

    /// The length the base64 value must have for this algorithm.
    const fn encoded_len(self) -> usize {
        match self {
            // 32 bytes, base64 without padding.
            Self::Sha256 => 43,
        }
    }
}

/// A subresource-integrity style digest: an algorithm and a base64 value.
///
/// One type rather than a bare string so the algorithm is never implicit. A digest whose algorithm
/// has to be inferred is one that will eventually be checked with the wrong one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SriDigest {
    algorithm: DigestAlgorithm,
    encoded: String,
}

impl SriDigest {
    /// Builds a digest from an algorithm and a base64 value.
    ///
    /// # Errors
    ///
    /// A description if the value is not the right length for the algorithm, or is not base64.
    pub fn new(algorithm: DigestAlgorithm, encoded: impl Into<String>) -> Result<Self, &'static str> {
        let encoded = encoded.into();
        if encoded.len() != algorithm.encoded_len() {
            return Err("digest has the wrong length for its algorithm");
        }
        // Base64 without padding: standard alphabet, and `=` is not expected here.
        if !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/')
        {
            return Err("digest is not base64");
        }
        Ok(Self { algorithm, encoded })
    }

    /// Which algorithm this digest uses.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The base64 value, without the algorithm prefix.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for SriDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm.prefix(), self.encoded)
    }
}

impl TryFrom<String> for SriDigest {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (prefix, encoded) = value
            .split_once('-')
            .ok_or("a digest must be `algorithm-base64`")?;
        let algorithm = match prefix {
            "sha256" => DigestAlgorithm::Sha256,
            _ => return Err("unknown digest algorithm"),
        };
        Self::new(algorithm, encoded)
    }
}

impl From<SriDigest> for String {
    fn from(value: SriDigest) -> Self {
        value.to_string()
    }
}

/// What a transfer carries, beyond its bytes.
///
/// A tagged enum so the receiver can reject a transfer whose metadata it does not understand
/// *before* accepting megabytes of data.
///
/// `rename_all_fields` rather than `rename_all`: the latter renames the *variants*, and the fields
/// inside each variant would keep their Rust names and go out as `plugin_id` where the protocol says
/// `pluginId`. Both attributes are needed, and the difference is invisible until a peer rejects the
/// message.
///
/// `deny_unknown_fields` is deliberately absent. It cannot be combined with `flatten` — the
/// enclosing [`TransferRequest`] flattens this enum — so a stray field here is ignored rather than
/// refused. The cost is accepted because the metadata is a hint about where bytes go, not a
/// capability: a field this version does not know cannot change what the receiver does with them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", rename_all_fields = "camelCase", tag = "metaKind")]
#[non_exhaustive]
pub enum TransferMeta {
    /// A plugin artifact on its way to be installed.
    #[serde(rename = "plugin-bundle")]
    PluginBundle {
        /// Which plugin.
        plugin_id: PluginId,
        /// Which version.
        version: String,
    },
    /// A file, with optional presentation details.
    #[serde(rename = "attachment")]
    Attachment {
        /// Suggested file name. Sanitised by the receiver before it is used on disk.
        file_name: String,
        /// Declared MIME type, if the sender knows it.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        mime_type: Option<String>,
        /// An opaque id grouping this file with an intent or a conversation.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        context_id: Option<String>,
    },
}

/// Proposes a transfer.
///
/// Note the absent `deny_unknown_fields`: serde cannot combine it with `flatten`, and the flattened
/// metadata needs to sit at the top level so a receiver sees one flat object rather than a nested
/// one it would have to unwrap before knowing whether the transfer is even for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    /// Identifies this transfer across both devices.
    pub transfer_id: TransferId,
    /// What kind of thing is being sent.
    pub kind: TransferKind,
    /// Total size in bytes.
    pub byte_length: u64,
    /// How the sender will split it. The receiver checks the sender keeps its word.
    pub chunk_size: u32,
    /// Digest of the whole object, checked before the transfer counts as successful.
    pub digest: SriDigest,
    /// Groups transfers that belong to one logical sync.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sync_session_id: Option<SessionId>,
    /// Kind-specific metadata.
    #[serde(flatten)]
    pub meta: TransferMeta,
}

/// One plugin as a peer describes it.
///
/// # Why this is not `synra_core::plugin_sync::RemoteState`
///
/// Because the wire has to be describable without the kernel: `RemoteState` is the kernel's opinion of a peer's plugin, and a
/// protocol type that leaned on it would make the protocol depend on the implementation it exists to describe. The mapping is
/// the kernel's, one field at a time, and it is the only place the two can disagree — which is why it is a mapping rather than
/// a `From`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSummary {
    /// Which plugin.
    pub plugin_id: PluginId,
    /// The version this device has, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,
    /// The digest of its artifact, if this device has one.
    ///
    /// The comparison that matters: two devices may hold the same version string with different bytes, and comparing versions
    /// alone would call that "already synchronised".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest: Option<String>,
    /// Whether it is running there.
    pub active: bool,
}

/// What a device answers when another asks what plugins it has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginList {
    /// Every plugin the answering device knows about, by identifier.
    pub plugins: Vec<PluginSummary>,
}
