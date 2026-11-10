use super::super::super::identity::SessionKey;
use super::super::super::record::PeerSession;
use super::super::super::state::{ClosureReason, LinkState};
use super::super::error::RegistryError;
use super::super::event::RegistryEvent;
use super::SessionRegistry;

impl SessionRegistry {
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
            let reason = session
                .closure
                .clone()
                .unwrap_or(ClosureReason::Local { why: String::new() });
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
    pub fn record_frame_in(&mut self, key: SessionKey, now_ms: u64) -> Result<(), RegistryError> {
        let session = self.session(key)?;
        if session.state.is_over() {
            let reason = session
                .closure
                .clone()
                .unwrap_or(ClosureReason::Local { why: String::new() });
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
            let reason = session
                .closure
                .clone()
                .unwrap_or(ClosureReason::Local { why: String::new() });
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
            self.close_inner(
                key,
                ClosureReason::HeartbeatMissed { silent_ms },
                &mut events,
            );
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
}
