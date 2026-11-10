use serde::{Deserialize, Serialize};

/// What resolving produced, which is what downloading needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    /// The version the source resolved to.
    pub version: String,
    /// Every file the package consists of, by name.
    pub artifacts: Vec<String>,
    /// The digest of the manifest, which grants are later recorded against.
    pub manifest_digest: String,
    /// Whether the source is one a development build is required for.
    pub development_only: bool,
}

/// How far a download has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// Bytes received.
    pub received: u64,
    /// Total bytes, when the source declared them.
    pub total: Option<u64>,
}

impl Progress {
    /// The fraction received, when the total is known.
    ///
    /// # Why this is an `Option` and not a `0.0`
    ///
    /// Because a progress bar at zero and a progress bar with no total are different things to draw, and collapsing
    /// them makes a chunked response with no `Content-Length` look like a download that has not started.
    #[must_use]
    pub fn fraction(&self) -> Option<f64> {
        let total = self.total?;
        if total == 0 {
            return Some(1.0);
        }
        Some((self.received as f64 / total as f64).clamp(0.0, 1.0))
    }

    /// Whether there is nothing left.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.total.is_some_and(|total| self.received >= total)
    }
}

/// What verification concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verified {
    /// The version.
    pub version: String,
    /// The digest of the artifact that was checked.
    pub artifact_digest: String,
    /// The digest of the manifest.
    pub manifest_digest: String,
    /// The capabilities the manifest asks for, which consent is about.
    pub requested: Vec<String>,
    /// Why the signature was accepted, when there was one.
    ///
    /// A sentence rather than a boolean because "signed by a publisher this device has seen before" and "signed by a
    /// publisher nobody has seen" are different answers, and the second one is what a user is being asked about.
    pub trust: Option<String>,
}

/// The user's decision about a plugin's capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Consent {
    /// The capabilities the user allowed.
    pub granted: Vec<String>,
    /// The ones they refused.
    pub denied: Vec<String>,
}

impl Consent {
    /// Whether anything was refused.
    ///
    /// Recorded because a plugin running with some capabilities denied behaves differently from one running with all
    /// of them, and a bug report that does not say which is a bug report about a different plugin.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        !self.denied.is_empty()
    }

    /// Whether every capability was refused, which is a refusal of the plugin.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        self.granted.is_empty() && !self.denied.is_empty()
    }
}
