//! How long a session lasts, the secret a UI plugin carries, what may be done with it, and why one was refused.

use synra_protocol::PluginId;
use synra_capability::CapabilitySet;

/// How long a session token is valid.
///
/// Twelve hours: longer than any plausible session of using a plugin, and short enough that a token which leaked out
/// of a page — through a screenshot of a debug console, say — is not usable the next day. There is no refresh: a
/// plugin that needs to keep working is reactivated by the interface, which issues a new token.
pub const SESSION_LIFETIME_MS: u64 = 12 * 60 * 60 * 1_000;

/// Why a call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionRefusal {
    /// No session has that nonce.
    ///
    /// Either it never existed, or it was revoked — and the two are the same answer on purpose: telling a plugin
    /// "you were deactivated" and "that token never existed" differently would let it probe for which plugins are
    /// installed.
    #[error("the session token is not valid")]
    Unknown,

    /// The session belongs to a different plugin than the call claims.
    #[error("the session belongs to {actual}, and the call claims {claimed}")]
    WrongPlugin {
        /// The plugin the session was issued to.
        actual: String,
        /// The plugin the call claims to be.
        claimed: String,
    },

    /// The session's time is up.
    #[error("the session expired {ago_ms}ms ago")]
    Expired {
        /// How long ago it expired.
        ago_ms: u64,
    },

    /// The plugin's version does not match the session's.
    ///
    /// An update replaces the artifact under a live page. Continuing with the old token would run the new code with
    /// the old grants and against the old artifact, so the version travel is refused and the page is reloaded.
    #[error("the session is for version {session}, and the call comes from {running}")]
    VersionChanged {
        /// The version the session was issued for.
        session: String,
        /// The version now installed.
        running: String,
    },
}

impl SessionRefusal {
    /// Whether an interface should reload the plugin's page.
    ///
    /// A version change is the one refusal where reloading fixes it, and the one where *not* reloading leaves a user
    /// with a page that fails every call for no visible reason. A revoked session is the opposite: reloading would
    /// restart a plugin the user just removed.
    #[must_use]
    pub fn means_reload(self) -> bool {
        matches!(self, Self::VersionChanged { .. } | Self::Expired { .. })
    }

    /// Whether the refusal means the plugin no longer exists as far as this session is concerned.
    ///
    /// The interface uses this to tear the page down rather than show an error inside it.
    #[must_use]
    pub fn means_teardown(self) -> bool {
        matches!(self, Self::Unknown | Self::WrongPlugin { .. })
    }
}

/// A session token, as the kernel holds it.
///
/// The plugin never sees this. It is given the nonce and nothing else — see the module docs for why that is the
/// whole point rather than a detail.
#[derive(Debug)]
pub struct UiSessionToken {
    /// Which plugin the session was issued to.
    pub plugin_id: PluginId,
    /// The version that was installed when it was issued.
    pub plugin_version: String,
    /// What the plugin was granted, frozen at activation.
    pub grants: CapabilitySet,
    /// When it was issued, in monotonic milliseconds.
    pub issued_at_ms: u64,
    /// Whether the plugin's own interface has finished loading.
    ///
    /// A page that has not reported itself ready has not yet registered its listeners, so an event delivered to it
    /// would be dropped. Reported rather than assumed, because "the WebView exists" and "the page is listening" are
    /// different facts and a plugin that misses its first event is a plugin with a bug nobody can reproduce.
    ///
    /// Atomic because `validate` holds the map's *read* guard: taking the write lock there would drop the guard the
    /// returned session borrows from, so the flag moves through an interior-mutability cell instead.
    pub(super) ready: core::sync::atomic::AtomicBool,
}

impl Clone for UiSessionToken {
    fn clone(&self) -> Self {
        Self {
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version.clone(),
            grants: self.grants.clone(),
            issued_at_ms: self.issued_at_ms,
            ready: core::sync::atomic::AtomicBool::new(self.is_ready()),
        }
    }
}

impl UiSessionToken {
    /// When it expires, in monotonic milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms.saturating_add(SESSION_LIFETIME_MS)
    }

    /// Whether it has expired at a reading.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms()
    }

    /// Whether the plugin's page has reported itself ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Records that the page is listening.
    pub fn mark_ready(&self) {
        self.ready.store(true, core::sync::atomic::Ordering::Relaxed);
    }
}
