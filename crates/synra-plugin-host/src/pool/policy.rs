//! When an instance is reused, recycled or evicted, and why a pool refuses.

use serde::{Deserialize, Serialize};
/// Whether a plugin's instances are interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum InstancePolicy {
    /// Memory does not persist between calls, so any instance will do.
    Stateless,
    /// Memory persists, so a conversation must keep the instance it started with.
    Stateful,
}

impl InstancePolicy {
    /// Whether instances may be handed to any caller.
    #[must_use]
    pub const fn allows_sharing(self) -> bool {
        matches!(self, Self::Stateless)
    }
}

/// Why an instance could not be handed out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PoolRefusal {
    /// Every instance is busy and the quota does not allow another.
    ///
    /// Retryable: an instance will be released. This is the refusal a caller waits on.
    #[error("every instance is busy, and the plugin's quota allows {limit}")]
    Exhausted {
        /// The quota.
        limit: u32,
        /// How long a caller should wait before asking again.
        retry_after_ms: u64,
    },

    /// A stateful plugin has no instance for this conversation and cannot make one.
    ///
    /// Not the same as [`Self::Exhausted`] because the caller cannot make progress by waiting: the conversation needs
    /// *its* instance, and waiting for someone else's to be released does not produce it. The caller's next step is to
    /// tell the user the plugin is at its limit, or to drop the conversation.
    #[error("the plugin is stateful and has no instance free for this conversation")]
    NoAffinity {
        /// The conversation that wanted one.
        conversation: String,
        /// How many instances exist.
        live: u32,
        /// The quota.
        limit: u32,
    },

    /// The plugin is not running.
    #[error("the plugin is not running")]
    NotRunning,

    /// An instance handle is not one this pool issued.
    ///
    /// Checked rather than assumed: a handle from a previous pool, or from a different plugin, would otherwise be
    /// released twice or released into the wrong pool.
    #[error("{handle} is not an instance of this pool")]
    UnknownInstance {
        /// The handle.
        handle: u64,
    },
}

impl PoolRefusal {
    /// Whether asking again later could succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Exhausted { .. })
    }
}
