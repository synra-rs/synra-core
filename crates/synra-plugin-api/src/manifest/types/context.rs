use serde::{Deserialize, Serialize};

/// What the plugin would like to be allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceHints {
    /// A memory budget in mebibytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preferred_memory_mb: Option<u32>,
    /// A per-call time budget in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preferred_timeout_ms: Option<u32>,
}

// ──────────────────────────────────────────────────────────────────────────────────────────────────────
// What the checks need from outside
// ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// What the checks need that is not in the manifest.
#[derive(Debug, Clone, Default)]
pub struct ManifestContext {
    /// The host SDK version, for the `sdk.min` comparison.
    pub host_sdk: Option<String>,
    /// The WIT world the host supports.
    pub host_wit: Option<String>,
    /// Artifacts that exist in the package, relative to its root.
    ///
    /// `None` skips the existence check, which is what the schema-level validation wants: a manifest can be
    /// checked for self-consistency before anything has been unpacked.
    ///
    /// A package walk produces a short ordered list; validation only needs membership checks.
    pub present_artifacts: Option<Vec<String>>,
}

/// The digest a consent decision is recorded against.
///
/// # ★ Why this is here rather than at each caller
///
/// Because two callers need it and they must agree to the byte. The shell records the user's decision against this
/// value; the daemon refuses to run a plugin whose manifest no longer hashes to what was recorded. Two implementations
/// that drifted — one hashing the parsed value, one the raw text — would produce a mismatch on every plugin, or worse,
/// a match for a manifest that had only been reformatted.
///
/// So it hashes the **bytes exactly as they are on disk**, which is why it takes text and not a [`Manifest`]: by the
/// time a manifest has been parsed, field order and whitespace are gone, and two files differing only in those would
/// hash alike.
///
/// SHA-256 in hex, and **not** an SRI string. Artifacts are signed and compared as SRI (`sha256-<base64>`); the manifest
/// is a text document rather than an addressed blob, and this is the encoding the plugin CLI signs and every recorded
/// consent decision carries. The two encodings differ on purpose — and using this function's sibling by accident is a
/// genuine signature reported as covering a different manifest, which is why the install and scan paths both call this
/// rather than hashing for themselves.
#[must_use]
pub fn manifest_digest(text: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}
