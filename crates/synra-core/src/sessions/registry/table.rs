//! The registry itself, and the transitions it permits.

use std::collections::BTreeMap;

use synra_protocol::handshake::{Agreed, LinkToken};
use synra_protocol::ids::{DeviceId, SessionId};
use synra_protocol::limits;
use synra_protocol::session::PlatformKind;

use super::event::RegistryEvent;
use super::super::identity::SessionKey;
use super::super::record::PeerSession;
use super::super::state::{ClosureReason, LinkState};
use super::error::RegistryError;

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
        self.live.get(&device).and_then(|key| self.sessions.get(key))
    }

    /// Every session, ordered by key.
    ///
    /// Ordered rather than in a `HashMap`'s order because a report and a test both want the same order twice.
    pub fn iter(&self) -> impl Iterator<Item = &PeerSession> {
        self.sessions.values()
    }

    /// Every session that can carry work.
    pub fn ready(&self) -> impl Iterator<Item = &PeerSession> {
        self.sessions.values().filter(|session| session.accepts_work())
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
        link_token: LinkToken,
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
            events.push(RegistryEvent::Replaced { old: old_key, new: SessionKey(self.next_key) });
        }

        let key = SessionKey(self.next_key);
        self.next_key = self.next_key.saturating_add(1);

        let session = PeerSession {
            key,
            session_id,
            device_id,
            platform,
            link_token,
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

    /// Begins draining, because a goodbye was sent or received.
    ///
    /// # Errors
    ///
    /// As [`SessionRegistry::begin_handshake`]. Draining a session that is already draining is allowed and changes
    /// nothing, because both ends sending a goodbye at once is ordinary rather than a mistake.
    pub fn begin_draining(&mut self, key: SessionKey, now_ms: u64) -> Result<(), RegistryError> {
        let session = self.session(key)?;
        if session.state == LinkState::Draining {
            return Ok(());
        }
        if session.state == LinkState::Closed {
            let reason = session.closure.clone().unwrap_or(ClosureReason::Local { why: String::new() });
            return Err(RegistryError::AlreadyClosed { key, reason });
        }
        self.transition(key, LinkState::Draining, now_ms)
    }

    /// Closes a session.
    ///
    /// Closing an already-closed session is not an error: a `bye` and a timeout can race, and the second one to arrive
    /// has nothing left to do. What it does not do is replace the recorded reason — the *first* reason is the true one,
    /// and a later one is a second explanation for the same event.
    pub fn close(
        &mut self,
        key: SessionKey,
        reason: ClosureReason,
        now_ms: u64,
    ) -> Vec<RegistryEvent> {
        let mut events = Vec::new();
        self.close_inner(key, reason, &mut events);
        // The clock is not read here — the caller passed it — but a session's last-seen is stamped so a report about a
        // session closed by a timeout says when, not just why.
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_seen_ms = session.last_seen_ms.max(now_ms.min(session.opened_at_ms));
        }
        events
    }

    /// Records that a frame arrived from the peer, moving the heartbeat deadline.
    ///
    /// # The token check
    ///
    /// A frame carrying a different link token is refused rather than applied. The case it exists for is a reconnect:
    /// the peer closed its old link and opened a new one, and a frame the old link sent just before it went away
    /// arrives after the new session is live. Applying it would let the dead link move the live session's state — for
    /// instance mark it as seen, keeping a session that is already gone alive for another timeout.
    ///
    /// # Errors
    ///
    /// [`RegistryError::TokenMismatch`], or as [`SessionRegistry::begin_handshake`].
    pub fn record_frame_in(
        &mut self,
        key: SessionKey,
        // By reference: the token is not consumed, and taking it by value would make every caller clone thirty-two
        // bytes to prove it knows a secret it already has.
        token: &LinkToken,
        now_ms: u64,
    ) -> Result<(), RegistryError> {
        let session = self.session(key)?;
        if &session.link_token != token {
            return Err(RegistryError::TokenMismatch { key });
        }
        if session.state.is_over() {
            let reason = session.closure.clone().unwrap_or(ClosureReason::Local { why: String::new() });
            return Err(RegistryError::AlreadyClosed { key, reason });
        }

        if let Some(session) = self.sessions.get_mut(&key) {
            session.frames_in = session.frames_in.saturating_add(1);
            session.last_seen_ms = now_ms;
            session.heartbeat_deadline_ms = now_ms.saturating_add(self.heartbeat_timeout_ms);
        }
        Ok(())
    }

    /// Records that a frame was sent.
    ///
    /// # Errors
    ///
    /// As [`SessionRegistry::begin_handshake`]. A frame may be sent while draining — the goodbye and the replies to
    /// work already in flight — but not after the link is over.
    pub fn record_frame_out(&mut self, key: SessionKey) -> Result<(), RegistryError> {
        let session = self.session(key)?;
        if !session.state.accepts_frames() {
            let reason = session.closure.clone().unwrap_or(ClosureReason::Local { why: String::new() });
            return Err(RegistryError::AlreadyClosed { key, reason });
        }
        if let Some(session) = self.sessions.get_mut(&key) {
            session.frames_out = session.frames_out.saturating_add(1);
        }
        Ok(())
    }

    /// Closes every session whose peer has been silent too long.
    ///
    /// # Why the whole sweep rather than one at a time
    ///
    /// The caller is a timer that runs on an interval, so one call has to handle every session that has expired since
    /// the last one. A method that handled one session would need the caller to keep asking which — which is the loop
    /// this is.
    ///
    /// Returns the events, in key order, so a report of one sweep is deterministic.
    pub fn sweep_expired(&mut self, now_ms: u64) -> Vec<RegistryEvent> {
        let overdue: Vec<(SessionKey, u64)> = self
            .sessions
            .values()
            .filter(|session| session.is_overdue(now_ms))
            .map(|session| (session.key, session.silent_for_ms(now_ms)))
            .collect();

        let mut events = Vec::new();
        for (key, silent_ms) in overdue {
            self.close_inner(key, ClosureReason::HeartbeatMissed { silent_ms }, &mut events);
        }
        events
    }

    /// Removes a closed session, so it stops appearing in a report.
    ///
    /// # Why a closed session is kept at all
    ///
    /// Because a user asking "why did it disconnect" asks *after* it disconnected, and by then the session is the only
    /// thing that knew. Keeping it until the caller removes it is what makes that answerable, and the caller removes it
    /// when the UI has shown it.
    ///
    /// # Errors
    ///
    /// [`RegistryError::NoSuchSession`], or [`RegistryError::AlreadyClosed`]'s opposite — a *live* session is not
    /// forgotten, because forgetting one leaves its peer connected with nothing tracking it.
    pub fn forget(&mut self, key: SessionKey) -> Result<PeerSession, RegistryError> {
        let Some(session) = self.sessions.get(&key) else {
            return Err(RegistryError::NoSuchSession(key));
        };
        if !session.state.is_over() {
            return Err(RegistryError::IllegalTransition {
                key,
                from: session.state,
                to: LinkState::Closed,
            });
        }
        let session = self.sessions.remove(&key).unwrap_or_else(|| unreachable!());
        // The `live` map is only ever pointed at a closed session by `close`, which does not remove it — so this is
        // where the two are brought back into agreement.
        if self.live.get(&session.device_id) == Some(&key) {
            self.live.remove(&session.device_id);
        }
        Ok(session)
    }

    /// Drops every closed session, and reports how many.
    ///
    /// For a caller that has already shown the reasons and wants the registry small again.
    pub fn forget_closed(&mut self) -> usize {
        let closed: Vec<SessionKey> = self
            .sessions
            .values()
            .filter(|session| session.state.is_over())
            .map(|session| session.key)
            .collect();
        let count = closed.len();
        for key in closed {
            let _ = self.forget(key);
        }
        count
    }

    /// A session, or the error explaining which of the two ways it is not usable.
    fn session(&self, key: SessionKey) -> Result<&PeerSession, RegistryError> {
        let session = self.sessions.get(&key).ok_or(RegistryError::NoSuchSession(key))?;
        if let Some(reason) = &session.closure {
            return Err(RegistryError::AlreadyClosed { key, reason: reason.clone() });
        }
        Ok(session)
    }

    /// Moves a session to a state, if the move is one a link may make.
    fn transition(
        &mut self,
        key: SessionKey,
        to: LinkState,
        now_ms: u64,
    ) -> Result<(), RegistryError> {
        let from = self.session(key)?.state;
        if from == to {
            return Ok(());
        }
        if !may_transition(from, to) {
            return Err(RegistryError::IllegalTransition { key, from, to });
        }
        if let Some(session) = self.sessions.get_mut(&key) {
            session.state = to;
            // A state change is activity: a session that just became ready is not one whose peer has been silent since
            // it opened.
            session.last_seen_ms = now_ms;
            session.heartbeat_deadline_ms = now_ms.saturating_add(self.heartbeat_timeout_ms);
        }
        Ok(())
    }

    /// Closes a session, recording the reason once.
    fn close_inner(&mut self, key: SessionKey, reason: ClosureReason, events: &mut Vec<RegistryEvent>) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        if session.state.is_over() {
            // ★ The first reason wins. A `bye` and a heartbeat timeout can race, and the second to arrive would
            // otherwise overwrite "the peer said goodbye" with "the peer was silent" — turning an ordinary close into a
            // network fault in the user's report.
            return;
        }
        session.state = LinkState::Closed;
        session.closure = Some(reason.clone());
        events.push(RegistryEvent::Closed(key, reason));
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a link may move from one state to another.
///
/// # Why a table rather than checks at each call site
///
/// The legal moves are a property of the state machine, and scattering them across the methods that make them means a
/// reader has to reconstruct the machine from five places. One function is the machine.
///
/// `Connecting` may go straight to `Ready`: a peer that answers a hello *with* an agreement has done both steps, and
/// requiring the kernel to pass through `Handshaking` would be requiring it to invent an event.
const fn may_transition(from: LinkState, to: LinkState) -> bool {
    match (from, to) {
        (LinkState::Connecting, LinkState::Handshaking | LinkState::Ready) => true,
        (LinkState::Handshaking, LinkState::Ready) => true,
        (LinkState::Ready, LinkState::Draining) => true,
        (LinkState::Connecting | LinkState::Handshaking | LinkState::Ready, LinkState::Closed) => true,
        (LinkState::Draining, LinkState::Closed) => true,
        // A link does not go back to a state it has left: a draining session that became ready again would take new
        // work after telling the peer it was going away.
        _ => false,
    }
}
