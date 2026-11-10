//! The registry itself, and the transitions it permits.

use std::collections::BTreeMap;

use synra_protocol::handshake::Agreed;
use synra_protocol::ids::{DeviceId, SessionId};
use synra_protocol::limits;
use synra_protocol::session::PlatformKind;

use super::super::identity::SessionKey;
use super::super::record::PeerSession;
use super::super::state::{ClosureReason, LinkState};
use super::error::RegistryError;
use super::event::RegistryEvent;

/// Everything the kernel knows about its links.
///
/// # Why one peer has at most one live session
///
/// Two live sessions to one device is a state nothing below can resolve: an envelope from that device arrives on one of
/// them and the kernel does not know which state it belongs to, half its work goes to each, and a `bye` on one does not
/// end the other. So opening a session for a peer that already has one **closes the old one** and says so, which is
/// what a reconnect is.
pub struct SessionRegistry {
    sessions: BTreeMap<SessionKey, PeerSession>,
    /// The live session for each device, so a reconnect can find what it replaces.
    live: BTreeMap<DeviceId, SessionKey>,
    next_key: u64,
    heartbeat_timeout_ms: u64,
}

impl SessionRegistry {
    /// A registry with no sessions and the protocol's heartbeat timeout.
    #[must_use]
    pub fn new() -> Self {
        Self::with_heartbeat_timeout(limits::HEARTBEAT_TIMEOUT.as_millis() as u64)
    }

    /// A registry whose sessions time out after `timeout_ms`.
    ///
    /// A zero timeout is raised to one millisecond rather than accepted: a session that is overdue the instant it opens
    /// is one the kernel would close before its handshake could finish, and the user would see a device that connects
    /// and immediately disconnects with no explanation.
    #[must_use]
    pub fn with_heartbeat_timeout(timeout_ms: u64) -> Self {
        Self {
            sessions: BTreeMap::new(),
            live: BTreeMap::new(),
            next_key: 1,
            heartbeat_timeout_ms: timeout_ms.max(1),
        }
    }

    /// How many sessions are tracked, closed ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// How long a session may go without hearing from its peer.
    #[must_use]
    pub const fn heartbeat_timeout_ms(&self) -> u64 {
        self.heartbeat_timeout_ms
    }

    /// A session by key.
    #[must_use]
    pub fn get(&self, key: SessionKey) -> Option<&PeerSession> {
        self.sessions.get(&key)
    }

    /// The live session for a device, if it has one.
    #[must_use]
    pub fn live_for(&self, device: DeviceId) -> Option<&PeerSession> {
        self.live
            .get(&device)
            .and_then(|key| self.sessions.get(key))
    }

    /// Every session, ordered by key.
    ///
    /// Ordered rather than in a `HashMap`'s order because a report and a test both want the same order twice.
    pub fn iter(&self) -> impl Iterator<Item = &PeerSession> {
        self.sessions.values()
    }

    /// Every session that can carry work.
    pub fn ready(&self) -> impl Iterator<Item = &PeerSession> {
        self.sessions
            .values()
            .filter(|session| session.accepts_work())
    }

    /// Opens a session for a peer.
    ///
    /// # The reconnect case
    ///
    /// A peer that already has a live session gets a new one, and the old is closed with [`ClosureReason::Local`]
    /// explaining what happened. The alternative — refusing the new session — is worse: the peer has already decided it
    /// is reconnecting, and refusing leaves the kernel talking to a link the peer has abandoned.
    pub fn open(
        &mut self,
        session_id: SessionId,
        device_id: DeviceId,
        platform: PlatformKind,
        now_ms: u64,
    ) -> (SessionKey, Vec<RegistryEvent>) {
        let mut events = Vec::new();

        if let Some(old_key) = self.live.get(&device_id).copied() {
            // The old session is closed before the new one is inserted, so the `live` map never points at a closed
            // session even for an instant.
            let reason = ClosureReason::Local {
                why: "the peer opened a new session".to_owned(),
            };
            self.close_inner(old_key, reason, &mut events);
            self.live.remove(&device_id);
            events.push(RegistryEvent::Replaced {
                old: old_key,
                new: SessionKey(self.next_key),
            });
        }

        let key = SessionKey(self.next_key);
        self.next_key = self.next_key.saturating_add(1);

        let session = PeerSession {
            key,
            session_id,
            device_id,
            platform,
            state: LinkState::Connecting,
            agreed: None,
            opened_at_ms: now_ms,
            last_seen_ms: now_ms,
            heartbeat_deadline_ms: now_ms.saturating_add(self.heartbeat_timeout_ms),
            closure: None,
            frames_in: 0,
            frames_out: 0,
        };
        self.sessions.insert(key, session);
        self.live.insert(device_id, key);
        // The `Replaced` event named the new key before it existed, so it is corrected here rather than the event being
        // built twice.
        for event in &mut events {
            if let RegistryEvent::Replaced { new, .. } = event {
                *new = key;
            }
        }
        events.push(RegistryEvent::Opened(key));
        (key, events)
    }

    /// Records that a peer said hello and the handshake is under way.
    ///
    /// # Errors
    ///
    /// [`RegistryError::AlreadyClosed`] or [`RegistryError::IllegalTransition`].
    pub fn begin_handshake(&mut self, key: SessionKey, now_ms: u64) -> Result<(), RegistryError> {
        self.transition(key, LinkState::Handshaking, now_ms)
    }

    /// Records an agreed handshake, so the link can carry work.
    ///
    /// # Errors
    ///
    /// As [`SessionRegistry::begin_handshake`].
    pub fn agree(
        &mut self,
        key: SessionKey,
        agreed: Agreed,
        now_ms: u64,
    ) -> Result<Vec<RegistryEvent>, RegistryError> {
        self.transition(key, LinkState::Ready, now_ms)?;
        // Written after the transition, so a session that could not become ready does not carry an agreement. The
        // agreement is what "ready" *means*, and the two disagreeing would be a link that is ready on terms nobody set.
        if let Some(session) = self.sessions.get_mut(&key) {
            session.agreed = Some(agreed);
        }
        Ok(vec![RegistryEvent::Ready(key)])
    }
}

mod operations;
mod transition;
