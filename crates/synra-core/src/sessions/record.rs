//! One link to one peer: its identity, and what is known about it.
//!
//! A record is deliberately a value rather than a handle — reading it cannot change a link's state, so a report and an
//! update cannot be confused.

use super::identity::SessionKey;
use super::state::{ClosureReason, LinkState};
use synra_protocol::handshake::{Agreed, LinkToken};
use synra_protocol::ids::{DeviceId, SessionId};
use synra_protocol::session::PlatformKind;
/// One link to one peer.
#[derive(Debug, Clone)]
pub struct PeerSession {
    pub(super) key: SessionKey,
    pub(super) session_id: SessionId,
    pub(super) device_id: DeviceId,
    pub(super) platform: PlatformKind,
    pub(super) link_token: LinkToken,
    pub(super) state: LinkState,
    pub(super) agreed: Option<Agreed>,
    pub(super) opened_at_ms: u64,
    pub(super) last_seen_ms: u64,
    /// When the peer must have spoken by.
    ///
    /// Stored rather than computed from `last_seen_ms + timeout`, so that a settings change mid-session does not
    /// silently move the deadline of a session already running.
    pub(super) heartbeat_deadline_ms: u64,
    pub(super) closure: Option<ClosureReason>,
    pub(super) frames_in: u64,
    pub(super) frames_out: u64,
}

impl PeerSession {
    /// The registry's key.
    #[must_use]
    pub const fn key(&self) -> SessionKey {
        self.key
    }

    /// The wire's identity for this session.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The peer.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// What the peer said it is.
    #[must_use]
    pub const fn platform(&self) -> PlatformKind {
        self.platform
    }

    /// The token this link was paired with.
    #[must_use]
    pub fn link_token(&self) -> LinkToken {
        // Cloned rather than copied: the token is thirty-two bytes of keyed hash and the protocol deliberately does not
        // make it `Copy`, because a token that can be copied implicitly is one that ends up in a log line.
        self.link_token.clone()
    }

    /// How far the link has got.
    #[must_use]
    pub const fn state(&self) -> LinkState {
        self.state
    }

    /// What both ends agreed on, once they have.
    #[must_use]
    pub const fn agreed(&self) -> Option<&Agreed> {
        self.agreed.as_ref()
    }

    /// When the session opened.
    #[must_use]
    pub const fn opened_at_ms(&self) -> u64 {
        self.opened_at_ms
    }

    /// When the peer last said anything.
    #[must_use]
    pub const fn last_seen_ms(&self) -> u64 {
        self.last_seen_ms
    }

    /// When the peer must have spoken by.
    #[must_use]
    pub const fn heartbeat_deadline_ms(&self) -> u64 {
        self.heartbeat_deadline_ms
    }

    /// Why it ended, once it has.
    #[must_use]
    pub const fn closure(&self) -> Option<&ClosureReason> {
        self.closure.as_ref()
    }

    /// Frames received on this session.
    #[must_use]
    pub const fn frames_in(&self) -> u64 {
        self.frames_in
    }

    /// Frames sent on this session.
    #[must_use]
    pub const fn frames_out(&self) -> u64 {
        self.frames_out
    }

    /// How long the peer has been silent, as of `now_ms`.
    ///
    /// Saturating rather than subtracting: a `now_ms` before the last activity is a caller with a clock that went
    /// backwards, and a negative silence is not a duration.
    #[must_use]
    pub const fn silent_for_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_seen_ms)
    }

    /// Whether the peer has been silent past the timeout.
    #[must_use]
    pub const fn is_overdue(&self, now_ms: u64) -> bool {
        now_ms >= self.heartbeat_deadline_ms && !self.state.is_over()
    }

    /// Whether the link can carry work.
    #[must_use]
    pub const fn accepts_work(&self) -> bool {
        self.state.accepts_work()
    }

    /// How long the session has been open, as of `now_ms`.
    #[must_use]
    pub const fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.opened_at_ms)
    }
}
