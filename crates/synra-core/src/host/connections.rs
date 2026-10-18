use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use synra_protocol::envelope::Envelope;
use synra_protocol::handshake::{LinkToken, PairingState};
use synra_protocol::ids::{DeviceId, SessionId};

use crate::link::PeerLink;
use crate::sessions::RegistryEvent;

use super::{Host, HostError, millis_reading};
use crate::peer::{Flags, LocalPeer, Negotiated};

/// A handshake that has finished, waiting to be recorded on a host.
///
/// ★ **Why the two halves of a dial are separate.**
///
/// `Host::dial` used to do everything: open the socket, exchange the handshake, record the session, build the link. The
/// network half needs nothing from the host but a **clone** of this device's peer record and its flags; the state half needs
/// `&mut Host` and touches no network at all. Keeping them in one method forced every caller to hold the host's lock across
/// a handshake — so a `devices` listing waited for a peer to finish saying `Hello`, which is exactly the report a user runs
/// while something is wrong.
///
/// The fields are private and there is no constructor but [`dial_peer`], because a `Dialled` that never completed a
/// handshake is a value that must not exist.
#[derive(Debug)]
pub struct Dialled {
    /// The connected socket, after the exchange.
    stream: TcpStream,
    /// What the two ends agreed.
    negotiated: Negotiated,
    /// The token that was presented, which the session records.
    token: Option<LinkToken>,
    /// Where it worked, which is the address a later attempt should use.
    address: SocketAddr,
}

/// Completes a handshake without a host, so a caller can do it **outside** its lock.
///
/// # Errors
///
/// [`HostError::Handshake`] for a failed exchange and [`HostError::Incompatible`] when the two ends agreed on something
/// unusable — the same failures [`Host::dial`] reports, because this is the half that produces them.
pub fn dial_peer(
    ours: &LocalPeer,
    flags: Flags,
    address: SocketAddr,
    token: Option<LinkToken>,
    now_ms: u64,
) -> Result<Dialled, HostError> {
    // Cloned before the call, because the token is also what the session records — and it is the token that was *used*,
    // which is what a later frame has to match.
    let offered = token.clone();
    let (stream, negotiated) = crate::peer::dial(address, ours, token, now_ms, flags)?;

    if !negotiated.is_usable() {
        // The two reached agreement and the agreement says they cannot work together. Reported as its own failure rather
        // than as a connection failure, because the user's next step is a version rather than a network.
        return Err(HostError::Incompatible {
            missing: format!("{:?}", negotiated.agreed.missing_required),
        });
    }

    Ok(Dialled { stream, negotiated, token: offered, address })
}

// The rest of `impl Host`, whose first part is in `kernel`.
impl Host {
    /// This device's peer record and its flags, cloned so a caller can dial without holding the host.
    ///
    /// The two things [`dial_peer`] needs and the host does not have to be present for. Everything else a dial reads or
    /// writes — the session registry, the trust level — happens in [`Host::adopt`], after the network is done.
    #[must_use]
    pub fn dialling_parts(&self) -> (LocalPeer, Flags) {
        (self.local.clone(), self.flags)
    }

    /// Records a completed handshake and returns the link. Touches no network.
    ///
    /// # Errors
    ///
    /// [`HostError::Bind`] when the session could not be marked ready, which cannot happen for one that was just opened —
    /// and is reported rather than dropped, because a session left in `Connecting` is one nothing routes to.
    pub fn adopt(&mut self, dialled: Dialled, now_ms: u64) -> Result<PeerLink, HostError> {
        let Dialled { stream, negotiated, token, address } = dialled;

        // ★ Now, and not before. The handshake proved which device is on the other end, so this is the first moment at
        // which recording a session attributes work correctly.
        // ★ The design's `links_opened_total`: a session exists, which is what "a link is open" means here.
        //
        // ★ Recorded where the session opens rather than on the way out, because that is the event. A link that opened
        // and then failed to be marked ready **did** open, and a count that hid it would make two different failures
        // look like one — the shape this codebase keeps removing.
        self.count_link_opened();
        let (key, _events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            // A token this dialler did not present is one the acceptor did not read, so the session records the token
            // that was used rather than inventing one.
            token.unwrap_or_else(|| LinkToken::from_bytes([0u8; LinkToken::LEN])),
            now_ms,
        );
        // A dialler has agreed by definition: the handshake completed. Recording it is what moves the session to ready,
        // and a failure here is impossible for a session that was just opened — but it is reported rather than dropped,
        // because a session that stayed in `Connecting` would be one nothing routes to.
        self.sessions
            .agree(key, negotiated.agreed.clone(), now_ms)
            .map_err(|error| HostError::Bind {
                address,
                why: format!("the session could not be marked ready: {error}"),
            })?;

        // The trust level rises here, with the address the connection actually worked at rather than the one that was
        // announced — which is what makes the next attempt succeed if the peer moved.
        self.discovery
            .handshaked(negotiated.device_id, address, Some(&negotiated.display_name), millis_reading(now_ms));

        let _ = &address;
        let mut link = PeerLink::new(
            stream,
            self.identity.device_id,
            negotiated.device_id,
            negotiated.agreed,
            self.flags,
        );
        // ★ The host's recorder, passed to the link it just made. Without this the byte counters stop at the API: the
        // host counts frames and the link owns the payloads, and a reader cannot add two numbers that were never taken.
        if let Some(metrics) = &self.metrics {
            link = link.with_metrics(Arc::clone(metrics));
        }
        Ok(link)
    }

    /// Dials a candidate and completes a handshake.
    ///
    /// # The order is the rule
    ///
    /// The session is created **after** the handshake, because the handshake is what establishes identity — a session
    /// for a device whose identity is unproven is one that attributes work to the wrong peer. And the trust level rises
    /// only once the connection completed, because a datagram is a hint and a connection is evidence.
    ///
    /// ★ **A caller that already holds the host's lock should not use this.** It is [`dial_peer`] and [`Host::adopt`] in
    /// one call, which is right for a test and wrong for a command: the lock ends up held across the exchange. The four
    /// command paths in `synra-daemon` use the halves.
    ///
    /// # Errors
    ///
    /// [`HostError::Handshake`] for a failed exchange, and [`HostError::Incompatible`] when the two devices reached
    /// agreement and the agreement is unusable.
    pub fn dial(
        &mut self,
        address: SocketAddr,
        token: Option<LinkToken>,
        now_ms: u64,
    ) -> Result<PeerLink, HostError> {
        let dialled = dial_peer(&self.local, self.flags, address, token, now_ms)?;
        self.adopt(dialled, now_ms)
    }

    /// Takes a connection if one is waiting, without handshaking on it.
    ///
    /// # Why this is separate from [`Host::accept`]
    ///
    /// Because the two halves are wildly different lengths. Taking a connection is a queue pop; a handshake is a read with
    /// a six-second timeout on it. A loop that did both would hold the host for as long as a peer took to say `Hello` —
    /// and a peer that connected and then went silent would freeze `devices` for six seconds, which is exactly the report a
    /// user runs while something is wrong.
    ///
    /// So the loop pops here, cheaply, and hands the socket to a thread that handshakes on it.
    ///
    /// # Errors
    ///
    /// [`HostError::Bind`] when this host is not listening, or when the listener cannot accept. A would-block is reported
    /// as `Ok(None)` rather than as an error, because "nothing is waiting" is not a failure.
    pub fn try_accept(&self) -> Result<Option<TcpStream>, HostError> {
        let Some(listener) = &self.listener else {
            return Err(HostError::Bind {
                address: SocketAddr::from(([0, 0, 0, 0], 0)),
                why: "this host is not listening".to_owned(),
            });
        };
        match listener.accept() {
            Ok((stream, _)) => {
                // ★ A connection accepted from a non-blocking listener **inherits** that mode on Windows, and every read on
                // it then fails with `WSAEWOULDBLOCK` (10035) — which the link reports as a transport failure, so an
                // incoming message looked like a broken connection. The listener has to be non-blocking for `try_accept` to
                // be a poll; the connection must not be, because the handshake and the read loop on it are both ordinary
                // blocking reads with timeouts of their own. Set back here rather than in the caller, because the caller
                // receives a value and cannot fix it afterwards.
                stream.set_nonblocking(false).map_err(|error| HostError::Bind {
                    address: listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
                    why: format!("the connection could not be made blocking: {error}"),
                })?;
                Ok(Some(stream))
            }
            // Nothing waiting. Not a failure: the caller loops and asks again.
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(HostError::Bind {
                address: listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
                why: error.to_string(),
            }),
        }
    }

    /// Puts a stream into non-blocking mode, so [`Host::try_accept`] can be polled.
    ///
    /// # Errors
    ///
    /// [`HostError::Bind`] when the operating system refuses.
    pub fn listen_nonblocking(&self) -> Result<(), HostError> {
        let Some(listener) = &self.listener else {
            return Err(HostError::Bind {
                address: SocketAddr::from(([0, 0, 0, 0], 0)),
                why: "this host is not listening".to_owned(),
            });
        };
        listener.set_nonblocking(true).map_err(|error| HostError::Bind {
            address: listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            why: error.to_string(),
        })
    }

    /// Completes a handshake on a connection that was already taken.
    ///
    /// # Errors
    ///
    /// [`HostError::Handshake`] when the exchange fails, and [`HostError::Incompatible`] when the two devices reach
    /// agreement and the agreement is unusable.
    pub fn complete_handshake(
        &mut self,
        stream: TcpStream,
        now_ms: u64,
        read_token: impl FnOnce(Option<&LinkToken>, DeviceId) -> PairingState,
    ) -> Result<(PeerLink, Vec<RegistryEvent>), HostError> {
        let address = stream.peer_addr().map_err(|error| HostError::Bind {
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            why: error.to_string(),
        })?;
        let (stream, negotiated) =
            crate::peer::accept_stream(stream, &self.local, now_ms, self.flags, read_token)?;

        if !negotiated.is_usable() {
            return Err(HostError::Incompatible {
                missing: format!("{:?}", negotiated.agreed.missing_required),
            });
        }

        let (key, mut events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            LinkToken::from_bytes([0u8; LinkToken::LEN]),
            now_ms,
        );
        if let Ok(ready) = self.sessions.agree(key, negotiated.agreed.clone(), now_ms) {
            events.extend(ready);
        }
        self.discovery.handshaked(
            negotiated.device_id,
            address,
            Some(&negotiated.display_name),
            millis_reading(now_ms),
        );

        let mut link = PeerLink::new(
            stream,
            self.identity.device_id,
            negotiated.device_id,
            negotiated.agreed,
            self.flags,
        );
        // Same recorder as the dialler's link: accepted and dialled connections are two halves of one network view.
        if let Some(metrics) = &self.metrics {
            link = link.with_metrics(Arc::clone(metrics));
        }
        Ok((link, events))
    }

    /// Accepts one connection and completes a handshake on it.
    ///
    /// # Errors
    ///
    /// [`HostError::Handshake`] when the exchange fails, and [`HostError::Bind`] when the listener cannot accept.
    pub fn accept(
        &mut self,
        now_ms: u64,
        read_token: impl FnOnce(Option<&LinkToken>, DeviceId) -> PairingState,
    ) -> Result<(PeerLink, Vec<RegistryEvent>), HostError> {
        let Some(listener) = &self.listener else {
            return Err(HostError::Bind {
                address: SocketAddr::from(([0, 0, 0, 0], 0)),
                why: "this host is not listening".to_owned(),
            });
        };

        // The peer's address is read before the handshake, because `accept` consumes the connection and the address is
        // what the discovery table records as having actually worked.
        let (stream, negotiated) =
            crate::peer::accept(listener, &self.local, now_ms, self.flags, read_token)?;
        let address = stream.peer_addr().map_err(|error| HostError::Bind {
            address: listener.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            why: error.to_string(),
        })?;

        if !negotiated.is_usable() {
            return Err(HostError::Incompatible {
                missing: format!("{:?}", negotiated.agreed.missing_required),
            });
        }

        let (key, mut events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            LinkToken::from_bytes([0u8; LinkToken::LEN]),
            now_ms,
        );
        // ★ The `Ready` event is appended rather than dropped. The first version used `let _ =`, which discarded the one
        // event a caller needs to know the session became usable — and the module's own test asserted it was there.
        if let Ok(ready) = self.sessions.agree(key, negotiated.agreed.clone(), now_ms) {
            events.extend(ready);
        }
        self.discovery.handshaked(
            negotiated.device_id,
            address,
            Some(&negotiated.display_name),
            millis_reading(now_ms),
        );

        let mut link = PeerLink::new(
            stream,
            self.identity.device_id,
            negotiated.device_id,
            negotiated.agreed,
            self.flags,
        );
        // Same recorder as the dialler's link: accepted and dialled connections are two halves of one network view.
        if let Some(metrics) = &self.metrics {
            link = link.with_metrics(Arc::clone(metrics));
        }
        Ok((link, events))
    }

    /// Whether a session for this link's peer is ready to carry a message, without sending one.
    ///
    /// ★ **Why the read is separate from the write.**
    ///
    /// `Host::send` did both, and needed `&mut self` for the accounting that follows the write — so a caller holding the
    /// host's lock held it across the write as well. A write is bounded by the socket's write timeout rather than by a
    /// timeout alone, and that is a much smaller window than a handshake, but it is the same shape of mistake: a lock held
    /// for the convenience of one method rather than for the state it protects.
    ///
    /// The session layer already writes through a link without the host (`session::send`). This is that shape, for the
    /// paths that go through `Host`.
    ///
    /// # Errors
    ///
    /// [`HostError::NoSession`] when there is no live session for that device. A session that is not ready **is** a
    /// refusal: the peer has not agreed yet, and a message sent now is one the other end will refuse.
    pub fn may_send(&self, link: &PeerLink) -> Result<(), HostError> {
        if self.sessions.live_for(link.peer()).is_none() {
            return Err(HostError::NoSession(link.peer()));
        }
        Ok(())
    }

    /// Counts a message that went out, so a report can say how many did.
    ///
    /// The only thing the write path needed `&mut self` for, which is why it is its own call.
    pub const fn count_sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    /// Sends an envelope on a session, counting it.
    ///
    /// ★ **A caller that holds the host's lock should use [`Host::may_send`], `PeerLink::send` and [`Host::count_sent`]
    /// directly** — this method is those three in one call, which is right for a test and wrong for a command.
    ///
    /// # Errors
    ///
    /// [`HostError::NoSession`] when there is no session for that device, [`HostError::Link`] when the write fails. A
    /// session that is not ready **is** a refusal: the peer has not agreed yet, and a message sent now is one the other
    /// end will refuse.
    pub fn send(&mut self, link: &mut PeerLink, envelope: &Envelope) -> Result<(), HostError> {
        self.may_send(link)?;
        link.send(envelope)?;
        self.count_sent();
        // ★ The design's `frames_sent_total{event}`: what this kernel said, and how much of it.
        //
        // ★ Recorded **after** the send rather than before, and that is not a detail: a frame the link refused never
        // left, so a count that included it would say this device talks more than it does.
        self.count_frame_sent(envelope.event.as_str());
        Ok(())
    }

}

impl Dialled {
    /// The link this handshake produced, ready to carry frames.
    ///
    /// # Why `local` and `flags` are arguments
    ///
    /// Because a dialled connection does not store its own identity: `dial_peer` was told `ours` to run the handshake, and
    /// keeping a second copy here would be a second answer to "whose connection is this" — the field the link checks every
    /// envelope against. The caller that dialled still has it.
    ///
    /// # Why this does not hand back the socket
    ///
    /// Because the socket is the point: a caller holding the `TcpStream` could write frames the handshake never agreed to,
    /// and `Link` is what enforces the agreement.
    #[must_use]
    pub fn into_link(self, local: DeviceId, flags: Flags) -> PeerLink {
        PeerLink::new(self.stream, local, self.negotiated.device_id, self.negotiated.agreed, flags)
    }
}
