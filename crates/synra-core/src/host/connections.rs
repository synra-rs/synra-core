use std::net::{SocketAddr, TcpStream};

use synra_protocol::envelope::Envelope;
use synra_protocol::handshake::{LinkToken, PairingState};
use synra_protocol::ids::{DeviceId, SessionId};

use crate::link::PeerLink;
use crate::sessions::RegistryEvent;

use super::{Host, HostError, millis_reading};

// The rest of `impl Host`, whose first part is in `kernel`.
impl Host {
    /// Dials a candidate and completes a handshake.
    ///
    /// # The order is the rule
    ///
    /// The session is created **after** the handshake, because the handshake is what establishes identity — a session
    /// for a device whose identity is unproven is one that attributes work to the wrong peer. And the trust level rises
    /// only once the connection completed, because a datagram is a hint and a connection is evidence.
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
        // Cloned before the call, because the token is also what the session records — and it is the token that was
        // *used*, which is what a later frame has to match.
        let offered = token.clone();
        let (stream, negotiated) =
            crate::peer::dial(address, &self.local, token, now_ms, self.flags)?;

        if !negotiated.is_usable() {
            // The two reached agreement and the agreement says they cannot work together. Reported as its own failure
            // rather than as a connection failure, because the user's next step is a version rather than a network.
            return Err(HostError::Incompatible {
                missing: format!("{:?}", negotiated.agreed.missing_required),
            });
        }

        // ★ Now, and not before. The handshake proved which device is on the other end, so this is the first moment at
        // which recording a session attributes work correctly.
        let (key, _events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            // A token this dialler did not present is one the acceptor did not read, so the session records the token
            // that was used rather than inventing one.
            offered.unwrap_or_else(|| LinkToken::from_bytes([0u8; LinkToken::LEN])),
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
        Ok(PeerLink::new(
            stream,
            self.identity.device_id,
            negotiated.device_id,
            negotiated.agreed,
            self.flags,
        ))
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

        Ok((
            PeerLink::new(
                stream,
                self.identity.device_id,
                negotiated.device_id,
                negotiated.agreed,
                self.flags,
            ),
            events,
        ))
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

        Ok((
            PeerLink::new(
                stream,
                self.identity.device_id,
                negotiated.device_id,
                negotiated.agreed,
                self.flags,
            ),
            events,
        ))
    }

    /// Sends an envelope on a session, counting it.
    ///
    /// # Errors
    ///
    /// [`HostError::NoSession`] when there is no session for that device, [`HostError::Link`] when the write fails. A
    /// session that is not ready **is** a refusal: the peer has not agreed yet, and a message sent now is one the other
    /// end will refuse.
    pub fn send(&mut self, link: &mut PeerLink, envelope: &Envelope) -> Result<(), HostError> {
        if self.sessions.live_for(link.peer()).is_none() {
            return Err(HostError::NoSession(link.peer()));
        }
        link.send(envelope)?;
        self.sent = self.sent.saturating_add(1);
        Ok(())
    }

}
