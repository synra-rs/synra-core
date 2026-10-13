//! The sessions the kernel has with its peers, and when they are over.
//!
//! # What this is for
//!
//! A link to another device is not one thing. It starts as a socket, becomes a session once both ends agree on a
//! version and a set of features, carries work while it is healthy, and ends — because one side said goodbye, because
//! the peer stopped answering, or because something failed. Each of those is a different answer to "may I send this on
//! that link", and a kernel without the distinction has to guess.
//!
//! The guesses are what this exists to remove. A message sent on a link whose handshake has not finished is one the
//! peer will refuse; a session kept alive after the peer disconnected is one the user can choose from a list and then
//! watch fail; a reconnect that left the old session in place is one where the same device appears twice and half the
//! work goes to the dead half.
//!
//! # Why time is passed in rather than read
//!
//! Every method that decides something about time takes `now_ms`. A registry that called the wall clock would be one
//! whose tests had to sleep, and whose answer depended on how long the test took — so a test of "a peer that stopped
//! answering is noticed after the timeout" would be a test that passes on a fast machine and flakes on a slow one.
//!
//! The clock is the caller's, which is also what the design document asks for: the kernel's decisions are pure
//! functions over values a caller supplies, so the tests need neither a network nor a sleeping thread.
//!
//! # Why the heartbeat deadline is stored rather than computed at the check
//!
//! A deadline that is `last_seen + timeout` is recomputed on every check, so *changing* the timeout mid-session
//! silently changes when the session dies. Storing the deadline means a session keeps the timing it started with, and a
//! settings change applies to new sessions — which is what a user changing a timeout expects.

use std::collections::BTreeMap;

use synra_protocol::handshake::{Agreed, LinkToken};
use synra_protocol::ids::{DeviceId, SessionId};
use synra_protocol::session::PlatformKind;
use synra_protocol::limits;

/// How far a link has got.
///
/// # Why this is a state rather than a set of flags
///
/// `connected`, `agreed` and `draining` as three booleans admit five states that cannot happen — draining and
/// connected, agreed and not connected, all three at once. A state that cannot happen is one that is never tested,
/// which means the day it happens nobody knows what it should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LinkState {
    /// The socket is open and nothing has been exchanged.
    Connecting,
    /// Both ends have said hello and neither has agreed yet.
    Handshaking,
    /// Agreed, and carrying work.
    Ready,
    /// A goodbye has been sent or received, and the link is finishing what it was doing.
    ///
    /// Distinct from [`LinkState::Ready`] because a link that is draining must not take new work — the peer is going
    /// away, and a transfer started now is one neither side will finish.
    Draining,
    /// Over. The registry keeps the entry only until the caller removes it, so a diagnostic can say why it ended.
    Closed,
}

impl LinkState {
    /// The name, for a log line or a report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Handshaking => "handshaking",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }

    /// Whether the link can carry work.
    ///
    /// # Why only `Ready`
    ///
    /// A draining link is the tempting exception — the peer said goodbye and a small message might still fit — and it
    /// is the wrong one. A goodbye means the peer is closing, and a message accepted on a closing link is one that
    /// either fails or, worse, arrives after the peer has released its state.
    #[must_use]
    pub const fn accepts_work(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether frames may still be exchanged.
    ///
    /// A `Draining` link must: the goodbye and the in-flight replies are frames. A `Closed` one must not.
    #[must_use]
    pub const fn accepts_frames(self) -> bool {
        matches!(self, Self::Connecting | Self::Handshaking | Self::Ready | Self::Draining)
    }

    /// Whether the link is over.
    #[must_use]
    pub const fn is_over(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Why a session ended.
///
/// # Why this is recorded rather than inferred
///
/// A closed entry and a closed entry with a reason look the same from the outside, and the questions a user asks —
/// "why did it disconnect", "is it my network" — are answered by the reason. Recording it costs a small enum, and
/// inferring it after the fact is impossible: by then the socket, the peer's goodbye and the timeout are all gone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClosureReason {
    /// This side closed it, for a user-visible reason.
    Local {
        /// What the user asked for, or why the kernel did it.
        why: String,
    },
    /// The peer said goodbye.
    Peer {
        /// The peer's reason, if it gave one.
        why: Option<String>,
    },
    /// The peer stopped answering.
    ///
    /// The one reason a session is closed by this side that the user did not cause, so it is separated from
    /// [`ClosureReason::Local`]: a UI that showed both as "disconnected" would hide a network fault behind an ordinary
    /// one.
    HeartbeatMissed {
        /// How long the peer had been silent.
        silent_ms: u64,
    },
    /// The handshake failed.
    HandshakeFailed {
        /// What went wrong.
        why: String,
    },
    /// The link failed at the transport.
    TransportFailed {
        /// What the transport said.
        why: String,
    },
}

impl ClosureReason {
    /// A sentence for a log line or a report.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::Local { why } => format!("closed locally: {why}"),
            Self::Peer { why } => match why {
                Some(why) => format!("the peer closed it: {why}"),
                None => "the peer closed it".to_owned(),
            },
            Self::HeartbeatMissed { silent_ms } => {
                format!("the peer was silent for {silent_ms} ms, longer than the heartbeat timeout")
            }
            Self::HandshakeFailed { why } => format!("the handshake failed: {why}"),
            Self::TransportFailed { why } => format!("the transport failed: {why}"),
        }
    }

    /// Whether the user should be told the link is down, as opposed to told what they asked for.
    ///
    /// # Why this is a question
    ///
    /// A user who pressed "disconnect" does not need a notification saying the device disconnected — they were there
    /// when it happened. A peer that stopped answering does, because they did not cause it and may not have noticed.
    #[must_use]
    pub const fn is_unexpected(&self) -> bool {
        matches!(
            self,
            Self::HeartbeatMissed { .. }
                | Self::HandshakeFailed { .. }
                | Self::TransportFailed { .. }
        )
    }
}

/// A session's identity, as the registry issued it.
///
/// # Why this is not `SessionId`
///
/// `SessionId` is the wire's identity for a session — what both ends put in an envelope. This is the *registry's* key,
/// and the difference matters on reconnect: the same peer makes a new session, and a caller holding the old
/// `SessionId` must not be handed the new session's state. Keeping the two apart is what makes that a type error rather
/// than a bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionKey(u64);

impl SessionKey {
    /// The number, for a log line or a report.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s{}", self.0)
    }
}

/// One link to one peer.
#[derive(Debug, Clone)]
pub struct PeerSession {
    key: SessionKey,
    session_id: SessionId,
    device_id: DeviceId,
    platform: PlatformKind,
    link_token: LinkToken,
    state: LinkState,
    agreed: Option<Agreed>,
    opened_at_ms: u64,
    last_seen_ms: u64,
    /// When the peer must have spoken by.
    ///
    /// Stored rather than computed from `last_seen_ms + timeout`, so that a settings change mid-session does not
    /// silently move the deadline of a session already running.
    heartbeat_deadline_ms: u64,
    closure: Option<ClosureReason>,
    frames_in: u64,
    frames_out: u64,
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

/// What the registry decided about a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryEvent {
    /// A session was opened.
    Opened(SessionKey),
    /// A session's handshake finished and it can carry work.
    Ready(SessionKey),
    /// A session began draining.
    Draining(SessionKey),
    /// A session ended, and why.
    Closed(SessionKey, ClosureReason),
    /// A peer opened a new session while an old one was alive, and the old one was closed.
    ///
    /// ★ The event a reconnect produces, and the one worth reporting: a UI that did not learn about it would show the
    /// device twice, and work sent to the old entry would go nowhere.
    Replaced {
        /// The session that ended.
        old: SessionKey,
        /// The session that replaced it.
        new: SessionKey,
    },
}

/// Why the registry refused something.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// There is no session with that key.
    #[error("no session {0}")]
    NoSuchSession(SessionKey),

    /// The session has ended.
    #[error("session {key} is closed: it ended because {}", .reason.explain())]
    AlreadyClosed {
        /// Which session.
        key: SessionKey,
        /// Why it ended.
        reason: ClosureReason,
    },

    /// The transition is not one a link may make.
    #[error("session {key} cannot go from {} to {}", .from.as_str(), .to.as_str())]
    IllegalTransition {
        /// Which session.
        key: SessionKey,
        /// Where it is.
        from: LinkState,
        /// Where it was asked to go.
        to: LinkState,
    },

    /// The link token does not match the one the session was opened with.
    ///
    /// A frame that arrives with the wrong token is one from a different link, or from before a reconnect, and applying
    /// it to this session would let the old link's frames move the new session's state.
    #[error("session {key} was opened with a different link token")]
    TokenMismatch {
        /// Which session.
        key: SessionKey,
    },
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::handshake::Feature;

    /// Two stable UUIDs, so a test can name the same device twice.
    const DEV_A: &str = "11111111-1111-4111-8111-111111111111";
    const DEV_B: &str = "22222222-2222-4222-8222-222222222222";
    const DEV_C: &str = "33333333-3333-4333-8333-333333333333";
    const SESSION_ONE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const SESSION_TWO: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    fn device(name: &str) -> DeviceId {
        // `DeviceId` is a UUID, so the tests name devices by parsing a UUID derived from a short name — which is what
        // the wire does and keeps the fixtures readable.
        name.parse().expect("a valid device id")
    }

    fn session_id(name: &str) -> SessionId {
        name.parse().expect("a valid session id")
    }

    fn token(byte: u8) -> LinkToken {
        LinkToken::from_bytes([byte; LinkToken::LEN])
    }

    /// Opens a session for a device no other fixture uses.
    ///
    /// The identities are freshly generated, because `DeviceId` and `SessionId` are UUIDs and a test that wants to name
    /// the same device twice uses [`opened_for`] with one of the constants above.
    fn opened(registry: &mut SessionRegistry, name: &str, at: u64) -> SessionKey {
        // The name is kept as a label for the call site's readability; the identity is the registry's.
        let _ = name;
        opened_random(registry, at)
    }

    /// Opens a session for a device whose identity is fresh.
    fn opened_random(registry: &mut SessionRegistry, at: u64) -> SessionKey {
        let (key, _) = registry.open(
            SessionId::new(),
            DeviceId::new(),
            PlatformKind::Desktop,
            token(1),
            at,
        );
        key
    }

    /// Opens a session for a *named* device, so a test can open a second and see what replaced the first.
    fn opened_for(registry: &mut SessionRegistry, device_id: DeviceId, at: u64) -> SessionKey {
        let (key, _) = registry.open(
            SessionId::new(),
            device_id,
            PlatformKind::Desktop,
            token(1),
            at,
        );
        key
    }

    fn agreed() -> Agreed {
        Agreed { common: vec![Feature::EventStream], missing_required: Vec::new() }
    }

    // ── Opening and the reconnect case ────────────────────────────────────────────────────────────

    #[test]
    fn opening_a_session_starts_it_connecting() {
        // The state a link is in before anything is exchanged. A registry that started at `Ready` would let the kernel
        // send work on a link the peer has not agreed to anything on.
        let mut registry = SessionRegistry::new();
        let key = opened_for(&mut registry, device(DEV_A), 1_000);
        let session = registry.get(key).expect("the session");

        assert_eq!(session.state(), LinkState::Connecting);
        assert!(!session.accepts_work());
        // And it accepts frames, because the hello is a frame.
        assert!(session.state().accepts_frames());
        assert_eq!(session.opened_at_ms(), 1_000);
        assert_eq!(session.device_id(), device(DEV_A));
    }

    #[test]
    fn opening_a_session_for_a_peer_that_has_one_closes_the_old() {
        // ★ A reconnect. Two live sessions to one device is a state nothing below can resolve: an envelope arrives on
        // one of them and the kernel does not know which state it belongs to, half its work goes to each, and a `bye`
        // on one does not end the other.
        let mut registry = SessionRegistry::new();
        let (old, _) = registry.open(
            session_id(SESSION_ONE),
            device(DEV_A),
            PlatformKind::Desktop,
            token(1),
            1_000,
        );
        let (new, events) = registry.open(
            session_id(SESSION_TWO),
            device(DEV_A),
            PlatformKind::Desktop,
            token(2),
            2_000,
        );

        assert_ne!(old, new);
        // The event names both, and the *new* key is the real one — the `Replaced` event is built before the new
        // session exists, so a registry that did not correct it would name a key nothing has.
        let replaced = events
            .iter()
            .find_map(|event| match event {
                RegistryEvent::Replaced { old, new } => Some((*old, *new)),
                _ => None,
            })
            .expect("a Replaced event");
        assert_eq!(replaced, (old, new));

        assert!(registry.get(old).expect("old").state().is_over());
        assert_eq!(registry.get(new).expect("new").state(), LinkState::Connecting);
        assert_eq!(registry.live_for(device(DEV_A)).expect("live").key(), new);
    }

    #[test]
    fn the_replaced_session_says_why_it_ended() {
        // The user asked nothing, so without a reason a UI would show an unexplained disconnect — and the explanation
        // is the one thing only the registry knows.
        let mut registry = SessionRegistry::new();
        let (old, _) = registry.open(
            session_id(SESSION_ONE),
            device(DEV_A),
            PlatformKind::Desktop,
            token(1),
            1_000,
        );
        registry.open(
            session_id(SESSION_TWO),
            device(DEV_A),
            PlatformKind::Desktop,
            token(2),
            2_000,
        );

        let reason = registry.get(old).expect("old").closure().expect("a reason");
        assert!(!reason.is_unexpected(), "a reconnect is not a network fault: {reason:?}");
        assert!(reason.explain().contains("new session"), "{}", reason.explain());
    }

    #[test]
    fn two_devices_have_two_sessions() {
        // The map is per device. A registry keyed only by session would let the second device's session replace the
        // first's `live` entry, and the first device would have no session the kernel could find.
        let mut registry = SessionRegistry::new();
        let a = opened_for(&mut registry, device(DEV_A), 1_000);
        let b = opened_for(&mut registry, device(DEV_B), 1_000);

        assert_eq!(registry.len(), 2);
        assert_eq!(registry.live_for(device(DEV_A)).expect("a").key(), a);
        assert_eq!(registry.live_for(device(DEV_B)).expect("b").key(), b);
        assert!(registry.live_for(device(DEV_C)).is_none());
    }

    #[test]
    fn the_keys_are_distinct_and_ordered() {
        // `BTreeMap` iteration order is the report's order, so the keys have to be ordered and distinct — two sessions
        // sharing a key is one session.
        let mut registry = SessionRegistry::new();
        let keys: Vec<SessionKey> = (0..5)
            .map(|_| opened_random(&mut registry, 1_000))
            .collect();

        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, keys);
    }

    // ── Transitions ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_link_becomes_ready_only_after_an_agreement() {
        // ★ The distinction the whole module exists for. A message sent on a link whose handshake has not finished is
        // one the peer will refuse, and `accepts_work` is what a caller checks before sending.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        assert!(!registry.get(key).expect("key").accepts_work());

        registry.begin_handshake(key, 1_100).expect("handshake");
        assert!(!registry.get(key).expect("key").accepts_work());

        let events = registry.agree(key, agreed(), 1_200).expect("agree");
        assert_eq!(events, vec![RegistryEvent::Ready(key)]);
        assert!(registry.get(key).expect("key").accepts_work());
        assert!(registry.get(key).expect("key").agreed().is_some());
    }

    #[test]
    fn connecting_may_become_ready_without_passing_through_handshaking() {
        // A peer that answers a hello *with* an agreement has done both steps. Requiring the kernel to pass through
        // `Handshaking` would be requiring it to invent an event it never observed.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.agree(key, agreed(), 1_100).expect("agree");
        assert_eq!(registry.get(key).expect("key").state(), LinkState::Ready);
    }

    #[test]
    fn a_link_does_not_go_back_to_a_state_it_left() {
        // ★ A draining session that became ready again would take new work after telling the peer it was going away —
        // and the peer may already have released its state for this session.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.agree(key, agreed(), 1_100).expect("agree");
        registry.begin_draining(key, 1_200).expect("drain");

        match registry.agree(key, agreed(), 1_300) {
            Err(RegistryError::IllegalTransition { from, to, .. }) => {
                assert_eq!(from, LinkState::Draining);
                assert_eq!(to, LinkState::Ready);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(registry.get(key).expect("key").state(), LinkState::Draining);
    }

    #[test]
    fn draining_twice_is_not_a_mistake() {
        // Both ends sending a goodbye at once is ordinary, so the second one has nothing to do rather than being an
        // error a caller has to handle.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.agree(key, agreed(), 1_100).expect("agree");
        registry.begin_draining(key, 1_200).expect("drain");
        assert!(registry.begin_draining(key, 1_300).is_ok());
        assert_eq!(registry.get(key).expect("key").state(), LinkState::Draining);
    }

    #[test]
    fn a_draining_link_still_exchanges_frames_but_takes_no_work() {
        // ★ The goodbye is a frame and the replies to work already in flight are frames. Refusing them would make a
        // clean close impossible, and accepting new work would start a transfer neither side will finish.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.agree(key, agreed(), 1_100).expect("agree");
        registry.begin_draining(key, 1_200).expect("drain");

        assert!(!registry.get(key).expect("key").accepts_work());
        assert!(registry.get(key).expect("key").state().accepts_frames());
        assert!(registry.record_frame_out(key).is_ok());
    }

    #[test]
    fn a_closed_link_takes_nothing() {
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.close(key, ClosureReason::Local { why: "the user asked".to_owned() }, 1_100);

        assert!(!registry.get(key).expect("key").state().accepts_frames());
        assert!(!registry.get(key).expect("key").accepts_work());
        assert!(matches!(
            registry.record_frame_out(key),
            Err(RegistryError::AlreadyClosed { .. })
        ));
    }

    #[test]
    fn a_transition_to_the_same_state_changes_nothing() {
        // A duplicate hello is not a mistake, and a registry that refused it would make a retransmitted frame an error
        // the caller has to swallow.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.begin_handshake(key, 1_100).expect("handshake");
        assert!(registry.begin_handshake(key, 1_200).is_ok());
        assert_eq!(registry.get(key).expect("key").state(), LinkState::Handshaking);
    }

    #[test]
    fn an_unknown_key_is_an_error_rather_than_a_panic() {
        // A stale key is ordinary — a timer firing after a session was forgotten — and a panic there would take the
        // kernel down for a scheduling mistake.
        let mut registry = SessionRegistry::new();
        let ghost = SessionKey(9_999);
        assert!(matches!(
            registry.begin_handshake(ghost, 1_000),
            Err(RegistryError::NoSuchSession(_))
        ));
        assert!(matches!(registry.record_frame_out(ghost), Err(RegistryError::NoSuchSession(_))));
        assert!(matches!(registry.forget(ghost), Err(RegistryError::NoSuchSession(_))));
        // And closing one is a no-op rather than an error: the caller has nothing to do about it.
        assert!(registry.close(ghost, ClosureReason::Local { why: String::new() }, 1_000).is_empty());
    }

    // ── The heartbeat ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_frame_from_the_peer_moves_the_deadline() {
        // The heartbeat is the only thing that distinguishes a quiet peer from a gone one, and it is evidence the peer
        // is there.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);

        registry.record_frame_in(key, &token(1), 800).expect("frame");
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_800);
        assert_eq!(registry.get(key).expect("key").frames_in(), 1);
    }

    #[test]
    fn a_frame_with_the_wrong_token_is_refused() {
        // ★ The reconnect case. The peer closed its old link and opened a new one, and a frame the old link sent just
        // before it went away arrives after the new session is live. Applying it would let the dead link move the live
        // session's state — for instance mark it as seen, keeping a session that is already gone alive for another
        // timeout.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);

        match registry.record_frame_in(key, &token(9), 500) {
            Err(RegistryError::TokenMismatch { key: reported }) => assert_eq!(reported, key),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And nothing moved.
        assert_eq!(registry.get(key).expect("key").last_seen_ms(), 0);
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);
    }

    #[test]
    fn a_sweep_closes_a_silent_peer_and_says_for_how_long() {
        // ★ The user-visible consequence: a device that was unplugged disappears from the list rather than staying
        // selectable and failing when chosen.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        registry.agree(key, agreed(), 0).expect("agree");

        let events = registry.sweep_expired(1_500);
        assert_eq!(events.len(), 1);
        match &events[0] {
            RegistryEvent::Closed(closed, ClosureReason::HeartbeatMissed { silent_ms }) => {
                assert_eq!(*closed, key);
                assert_eq!(*silent_ms, 1_500);
            }
            other => panic!("expected a heartbeat closure, got {other:?}"),
        }
        assert!(registry.get(key).expect("key").state().is_over());
        // And it is the *unexpected* kind, so a UI tells the user rather than staying silent as it would for a close
        // the user asked for.
        let reason = registry.get(key).expect("key").closure().expect("a reason");
        assert!(reason.is_unexpected());
    }

    #[test]
    fn a_sweep_before_the_deadline_closes_nothing() {
        // The boundary. A sweep that fired one millisecond early would disconnect a peer that is answering, and the
        // symptom is a link that drops every few seconds for no reason a user can see.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        assert!(registry.sweep_expired(999).is_empty());
        assert_eq!(registry.get(key).expect("key").state(), LinkState::Connecting);
    }

    #[test]
    fn a_sweep_handles_every_session_that_expired() {
        // The caller is a timer on an interval, so one call has to handle every session that expired since the last
        // one. A method that handled one would need the caller to keep asking which — which is this loop.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let a = opened(&mut registry, "a", 0);
        let b = opened(&mut registry, "b", 0);
        let fresh = opened(&mut registry, "c", 900);
        registry.record_frame_in(fresh, &token(1), 950).expect("frame");

        let events = registry.sweep_expired(1_500);
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(registry.get(a).expect("a").state().is_over());
        assert!(registry.get(b).expect("b").state().is_over());
        // The one that spoke is untouched.
        assert!(!registry.get(fresh).expect("fresh").state().is_over());
    }

    #[test]
    fn a_second_sweep_does_not_close_what_is_already_closed() {
        // ★ The first reason wins. Without this, a sweep after a `bye` would replace "the peer said goodbye" with "the
        // peer was silent" — turning an ordinary close into a network fault in the user's report, and double-counting
        // the closure in a log.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        registry.close(key, ClosureReason::Peer { why: None }, 500);

        assert!(registry.sweep_expired(5_000).is_empty());
        let reason = registry.get(key).expect("key").closure().expect("a reason");
        assert!(matches!(reason, ClosureReason::Peer { .. }), "{reason:?}");
    }

    #[test]
    fn closing_a_closed_session_does_not_replace_the_reason() {
        // A `bye` and a timeout can race, and the second to arrive has nothing left to do — but it must not overwrite
        // the first explanation.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        registry.close(key, ClosureReason::Peer { why: Some("done".to_owned()) }, 100);
        let events = registry.close(
            key,
            ClosureReason::HeartbeatMissed { silent_ms: 9_000 },
            9_000,
        );

        assert!(events.is_empty(), "{events:?}");
        assert!(matches!(
            registry.get(key).expect("key").closure(),
            Some(ClosureReason::Peer { .. })
        ));
    }

    #[test]
    fn a_handshake_that_takes_longer_than_the_timeout_is_closed() {
        // A peer that opened a socket and said nothing. Without the sweep it would hold a session forever, and a device
        // that is powered off mid-scan would stay in the list.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        let events = registry.sweep_expired(2_000);
        assert_eq!(events.len(), 1);
        assert!(registry.get(key).expect("key").state().is_over());
    }

    #[test]
    fn a_zero_timeout_is_raised_rather_than_accepted() {
        // ★ A session that is overdue the instant it opens is one the kernel would close before its handshake could
        // finish, and the user would see a device that connects and immediately disconnects with no explanation.
        let registry = SessionRegistry::with_heartbeat_timeout(0);
        assert_eq!(registry.heartbeat_timeout_ms(), 1);
    }

    #[test]
    fn the_default_timeout_is_the_protocols() {
        // The registry does not invent a figure: the constant is the protocol's, and a registry with its own would time
        // out a peer at a different moment from every other part of the kernel.
        let registry = SessionRegistry::new();
        assert_eq!(
            registry.heartbeat_timeout_ms(),
            limits::HEARTBEAT_TIMEOUT.as_millis() as u64
        );
    }

    #[test]
    fn a_deadline_is_stored_rather_than_recomputed() {
        // ★ Changing the timeout mid-session does not move a running session's deadline. A deadline computed as
        // `last_seen + timeout` at the check would move it, so a user raising the timeout would silently extend the
        // life of a session that is already gone.
        let mut registry = SessionRegistry::with_heartbeat_timeout(1_000);
        let key = opened(&mut registry, "a", 0);
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);

        // A new registry would have a different timeout; this session keeps its own.
        let other = SessionRegistry::with_heartbeat_timeout(5_000);
        assert_eq!(other.heartbeat_timeout_ms(), 5_000);
        assert_eq!(registry.get(key).expect("key").heartbeat_deadline_ms(), 1_000);
    }

    // ── Accounting ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn frames_are_counted_in_both_directions() {
        // The numbers a diagnostic report wants, and the only evidence of a link that is up but not carrying anything —
        // frames out and none in is a peer that is not listening.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 0);
        for _ in 0..3 {
            registry.record_frame_out(key).expect("out");
        }
        registry.record_frame_in(key, &token(1), 100).expect("in");

        let session = registry.get(key).expect("key");
        assert_eq!(session.frames_out(), 3);
        assert_eq!(session.frames_in(), 1);
    }

    #[test]
    fn the_age_and_the_silence_are_measured_from_different_moments() {
        // ★ Two different questions. A session that has been open for an hour and heard from its peer a second ago is
        // healthy; one open for an hour and silent for an hour is not. Deriving one from the other would report the
        // wrong one for exactly the long-lived sessions that matter.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 1000);
        registry.record_frame_in(key, &token(1), 3_600_000).expect("frame");

        let session = registry.get(key).expect("key");
        assert_eq!(session.age_ms(3_600_000), 3_599_000);
        assert_eq!(session.silent_for_ms(3_600_000), 0);
        assert!(!session.is_overdue(3_600_000));
    }

    #[test]
    fn a_clock_that_went_backwards_does_not_report_a_negative_silence() {
        // A caller with a clock that moved backwards is a caller with a problem, and a negative duration is not one this
        // module can represent. Saturating is the answer that keeps the arithmetic total.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 5_000);
        let session = registry.get(key).expect("key");
        assert_eq!(session.silent_for_ms(1_000), 0);
        assert_eq!(session.age_ms(1_000), 0);
    }

    // ── Forgetting ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_closed_session_is_kept_until_it_is_forgotten() {
        // ★ A user asking "why did it disconnect" asks *after* it disconnected, and by then the session is the only
        // thing that knew. Keeping it until the caller removes it is what makes that answerable.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 0);
        registry.close(key, ClosureReason::TransportFailed { why: "reset".to_owned() }, 100);

        assert_eq!(registry.len(), 1);
        let forgotten = registry.forget(key).expect("forget");
        assert!(forgotten.closure().expect("reason").explain().contains("reset"));
        assert!(registry.is_empty());
        assert!(registry.live_for(device(DEV_A)).is_none());
    }

    #[test]
    fn a_live_session_is_not_forgotten() {
        // ★ Forgetting a live one leaves its peer connected with nothing tracking it: no heartbeat, no timeout, no way
        // to close it. The refusal is what makes the caller close it first.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 0);
        match registry.forget(key) {
            Err(RegistryError::IllegalTransition { from, .. }) => {
                assert_eq!(from, LinkState::Connecting);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn forgetting_every_closed_session_leaves_the_live_ones() {
        let mut registry = SessionRegistry::new();
        let a = opened(&mut registry, "a", 0);
        let b = opened(&mut registry, "b", 0);
        let c = opened(&mut registry, "c", 0);
        registry.close(a, ClosureReason::Peer { why: None }, 100);
        registry.close(b, ClosureReason::Peer { why: None }, 100);

        assert_eq!(registry.forget_closed(), 2);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(c).expect("c").state(), LinkState::Connecting);
    }

    #[test]
    fn forgetting_every_closed_session_removes_their_live_entries() {
        // ★ The two maps have to agree. A `live` entry pointing at a forgotten session is one where `live_for` returns
        // `None` while the map says the device has a session — so the next reconnect would find nothing to replace and
        // the device would appear twice after all.
        let mut registry = SessionRegistry::new();
        let key = opened(&mut registry, "a", 0);
        registry.close(key, ClosureReason::Peer { why: None }, 100);
        registry.forget_closed();

        assert!(registry.live_for(device(DEV_A)).is_none());
        // And a reconnect is a fresh open rather than a replacement.
        let (new, events) = registry.open(
            session_id(SESSION_TWO),
            device(DEV_A),
            PlatformKind::Desktop,
            token(2),
            200,
        );
        assert!(!events.iter().any(|event| matches!(event, RegistryEvent::Replaced { .. })));
        assert_eq!(registry.get(new).expect("new").state(), LinkState::Connecting);
    }

    #[test]
    fn the_ready_list_is_the_sessions_that_accept_work() {
        // What a UI asks for when it wants to offer a device, and the one list that must not include a link whose
        // handshake has not finished or one that is draining.
        let mut registry = SessionRegistry::new();
        let connecting = opened(&mut registry, "a", 0);
        let ready = opened(&mut registry, "b", 0);
        let draining = opened(&mut registry, "c", 0);
        registry.agree(ready, agreed(), 10).expect("agree");
        registry.agree(draining, agreed(), 10).expect("agree");
        registry.begin_draining(draining, 20).expect("drain");

        let keys: Vec<SessionKey> = registry.ready().map(PeerSession::key).collect();
        assert_eq!(keys, vec![ready]);
        assert!(!keys.contains(&connecting));
    }

    #[test]
    fn a_report_of_the_states_says_which_is_which() {
        // The names reach a log line and a diagnostic bundle, and a reader has to tell a draining link from a closed
        // one to know whether the peer is going away or gone.
        assert_eq!(LinkState::Connecting.as_str(), "connecting");
        assert_eq!(LinkState::Handshaking.as_str(), "handshaking");
        assert_eq!(LinkState::Ready.as_str(), "ready");
        assert_eq!(LinkState::Draining.as_str(), "draining");
        assert_eq!(LinkState::Closed.as_str(), "closed");
        assert!(LinkState::Closed.is_over());
        assert!(!LinkState::Draining.is_over());
    }

    #[test]
    fn only_the_reasons_the_user_did_not_cause_are_unexpected() {
        // ★ A user who pressed "disconnect" does not need a notification saying the device disconnected — they were
        // there when it happened. A peer that stopped answering does, because they did not cause it.
        assert!(!ClosureReason::Local { why: "asked".to_owned() }.is_unexpected());
        assert!(!ClosureReason::Peer { why: None }.is_unexpected());
        assert!(ClosureReason::HeartbeatMissed { silent_ms: 1 }.is_unexpected());
        assert!(ClosureReason::HandshakeFailed { why: "v".to_owned() }.is_unexpected());
        assert!(ClosureReason::TransportFailed { why: "e".to_owned() }.is_unexpected());
    }

    #[test]
    fn every_reason_explains_itself_for_a_log_line() {
        // These sentences reach a user's diagnostic bundle, and one that contained a brace would be a debugging aid that
        // looks like a bug.
        for reason in [
            ClosureReason::Local { why: "the user asked".to_owned() },
            ClosureReason::Peer { why: Some("done".to_owned()) },
            ClosureReason::Peer { why: None },
            ClosureReason::HeartbeatMissed { silent_ms: 90_000 },
            ClosureReason::HandshakeFailed { why: "no shared feature".to_owned() },
            ClosureReason::TransportFailed { why: "reset by peer".to_owned() },
        ] {
            let text = reason.explain();
            assert!(text.len() > 15, "{reason:?} -> {text}");
            assert!(!text.contains('{'), "{reason:?} -> {text}");
            assert!(!text.contains('}'), "{reason:?} -> {text}");
        }
    }

    #[test]
    fn the_errors_explain_themselves() {
        let key = SessionKey(3);
        let errors = [
            RegistryError::NoSuchSession(key),
            RegistryError::AlreadyClosed {
                key,
                reason: ClosureReason::Peer { why: Some("done".to_owned()) },
            },
            RegistryError::IllegalTransition {
                key,
                from: LinkState::Draining,
                to: LinkState::Ready,
            },
            RegistryError::TokenMismatch { key },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.contains('3'), "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn a_key_is_readable_in_a_report() {
        assert_eq!(SessionKey(7).to_string(), "s7");
        assert_eq!(SessionKey(7).get(), 7);
    }

    #[test]
    fn the_registry_iterates_in_key_order() {
        // A report and a test both want the same order twice, so the store is ordered rather than a `HashMap`.
        let mut registry = SessionRegistry::new();
        let keys: Vec<SessionKey> = (0..4)
            .map(|_| opened_random(&mut registry, 1_000))
            .collect();
        let iterated: Vec<SessionKey> = registry.iter().map(PeerSession::key).collect();
        assert_eq!(iterated, keys);
    }

    #[test]
    fn an_empty_registry_says_so() {
        let mut registry = SessionRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.ready().next().is_none());
        assert!(registry.sweep_expired(1_000_000).is_empty());
        assert_eq!(registry.forget_closed(), 0);
        assert_eq!(SessionRegistry::default().len(), 0);
    }
}
