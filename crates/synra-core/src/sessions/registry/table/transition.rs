use super::super::super::identity::SessionKey;
use super::super::super::record::PeerSession;
use super::super::super::state::{ClosureReason, LinkState};
use super::super::error::RegistryError;
use super::super::event::RegistryEvent;
use super::SessionRegistry;

impl SessionRegistry {
    /// A session, or the error explaining which of the two ways it is not usable.
    pub(in crate::sessions::registry::table) fn session(
        &self,
        key: SessionKey,
    ) -> Result<&PeerSession, RegistryError> {
        let session = self
            .sessions
            .get(&key)
            .ok_or(RegistryError::NoSuchSession(key))?;
        if let Some(reason) = &session.closure {
            return Err(RegistryError::AlreadyClosed {
                key,
                reason: reason.clone(),
            });
        }
        Ok(session)
    }

    /// Moves a session to a state, if the move is one a link may make.
    pub(in crate::sessions::registry::table) fn transition(
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
    pub(in crate::sessions::registry::table) fn close_inner(
        &mut self,
        key: SessionKey,
        reason: ClosureReason,
        events: &mut Vec<RegistryEvent>,
    ) {
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
        (LinkState::Connecting | LinkState::Handshaking | LinkState::Ready, LinkState::Closed) => {
            true
        }
        (LinkState::Draining, LinkState::Closed) => true,
        // A link does not go back to a state it has left: a draining session that became ready again would take new
        // work after telling the peer it was going away.
        _ => false,
    }
}
