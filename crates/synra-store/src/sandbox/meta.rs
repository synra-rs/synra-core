use serde::{Deserialize, Serialize};

/// What the sandbox records about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxMeta {
    /// The plugin the sandbox belongs to.
    pub plugin_id: String,
    /// Bytes used under `files/`, as of the last count.
    pub files_bytes: u64,
    /// Bytes used under `cache/`.
    pub cache_bytes: u64,
    /// When usage was last measured, in milliseconds since the epoch.
    pub measured_at_ms: i64,
}

impl SandboxMeta {
    /// An empty record for a plugin.
    #[must_use]
    pub fn new(plugin_id: impl Into<String>, measured_at_ms: i64) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            files_bytes: 0,
            cache_bytes: 0,
            measured_at_ms,
        }
    }

    /// Total bytes the plugin is using.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.files_bytes.saturating_add(self.cache_bytes)
    }

    /// Whether the cache may be cleared without losing data.
    ///
    /// Always, by the definition of the directory; the method exists so the interface does not have to encode
    /// that knowledge.
    #[must_use]
    pub const fn is_cache_disposable(&self) -> bool {
        true
    }
}
