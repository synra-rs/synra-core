//! A session a caller has already had accepted.

use synra_protocol::PluginId;

use super::token::UiSessionToken;
use synra_capability::CapabilitySet;

/// A validated session, as a caller sees it.
///
/// # Held by value, not borrowed
///
/// The token is an `Arc`, so the session outlives the registry's guard rather than borrowing from it. That matters
/// for two reasons: `validate` can return without holding a read lock for the duration of a call — a read lock held
/// across a call is a write lock that waits, which is how a revocation ends up blocked behind the very call it is
/// revoking — and the caller cannot accidentally keep a guard alive in a struct field, which is the shape that
/// deadlocks a registry with itself.
///
/// It also means a revocation does not invalidate a session that is already in flight. That is deliberate: a call
/// that passed validation is one the kernel decided to allow, and aborting it halfway would leave the plugin's state
/// and the kernel's disagreeing. The *next* call is refused, which is what "deactivated" means for a page the kernel
/// cannot reach into.
#[derive(Debug, Clone)]
pub struct ValidatedSession {
    /// The nonce, for an audit record.
    pub nonce: u128,
    /// The token.
    pub(super) token: std::sync::Arc<UiSessionToken>,
}

impl ValidatedSession {
    /// The token.
    #[must_use]
    pub fn token(&self) -> &UiSessionToken {
        &self.token
    }

    /// The plugin the session belongs to.
    #[must_use]
    pub fn plugin_id(&self) -> &PluginId {
        &self.token.plugin_id
    }

    /// What the plugin may do, as of activation.
    #[must_use]
    pub fn grants(&self) -> &CapabilitySet {
        &self.token.grants
    }

    /// Whether the plugin's page has reported itself ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.token.is_ready()
    }
}
