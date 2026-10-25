use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use synra_protocol::envelope::Envelope;
use synra_protocol::handshake::LinkToken;
use synra_protocol::ids::{DeviceId, SessionId};

use crate::link::PeerLink;
use crate::sessions::RegistryEvent;

use super::{Host, HostError, millis_reading};
use crate::peer::authenticated::AuthenticatedPeer;
use crate::peer::{Flags, Negotiated};

/// A validated authentication snapshot, cloned before network IO so no host mutex is held.
#[derive(Clone)]
pub struct DialConfig {
    network: Result<AuthenticatedPeer, String>,
}

impl DialConfig {
    fn ready(&self) -> Result<&AuthenticatedPeer, HostError> {
        self.network
            .as_ref()
            .map_err(|why| HostError::NetworkUnavailable { why: why.clone() })
    }

    /// Authenticates an accepted socket outside the host lock, retaining its credential generation.
    /// # Errors
    /// Refuses unavailable credentials, unapproved peers, invalid TLS and mismatched Hello identities.
    pub fn accept_stream(
        &self,
        stream: TcpStream,
        flags: Flags,
        now_ms: u64,
    ) -> Result<Dialled, HostError> {
        let address = stream.peer_addr().map_err(|error| HostError::Bind {
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            why: error.to_string(),
        })?;
        let (link, negotiated) = self
            .ready()?
            .accept(
                stream,
                now_ms,
                now_ms / 1000,
                flags
                    .timeout
                    .unwrap_or(synra_protocol::limits::HELLO_TIMEOUT),
            )
            .map_err(connection_error)?;
        Ok(Dialled {
            link,
            negotiated,
            address,
        })
    }
}

/// An authenticated application handshake waiting to be recorded in the host.
#[derive(Debug)]
pub struct Dialled {
    link: PeerLink,
    negotiated: Negotiated,
    address: SocketAddr,
}

/// Opens an authenticated business connection to the exact requested device outside the host lock.
/// # Errors
/// Refuses missing durable approvals, connection failures, mismatched TLS identities and invalid Hello.
pub fn dial_peer(
    ours: &DialConfig,
    flags: Flags,
    address: SocketAddr,
    peer: DeviceId,
    now_ms: u64,
) -> Result<Dialled, HostError> {
    let (link, negotiated) = ours
        .ready()?
        .dial(
            address,
            peer,
            now_ms,
            now_ms / 1000,
            flags
                .timeout
                .unwrap_or(synra_protocol::limits::HELLO_TIMEOUT),
        )
        .map_err(connection_error)?;
    Ok(Dialled {
        link,
        negotiated,
        address,
    })
}

fn connection_error(error: crate::peer::authenticated::SecurePeerError) -> HostError {
    use crate::peer::authenticated::SecurePeerError;
    use synra_net::authentication::AuthenticationError;
    match error {
        SecurePeerError::Authentication(AuthenticationError::Transport(why)) => {
            HostError::Handshake(crate::peer::HandshakeError::Transport { why })
        }
        SecurePeerError::Authentication(AuthenticationError::TimedOut) => {
            HostError::Link(crate::link::LinkError::TimedOut)
        }
        SecurePeerError::Handshake(error) => HostError::Handshake(error),
        SecurePeerError::Authorization(error) => HostError::Link(error),
        SecurePeerError::Trust(crate::peer_trust::TrustError::Database(why)) => {
            HostError::Link(crate::link::LinkError::AuthorizationUnavailable { why })
        }
        other => HostError::Authentication {
            why: other.to_string(),
        },
    }
}

// The rest of `impl Host`, whose first part is in `kernel`.
impl Host {
    /// Clones authentication and profile metadata for network IO outside the host mutex.
    #[must_use]
    pub fn dialling_parts(&self) -> (DialConfig, Flags) {
        let network = self
            .network
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|network| {
                network
                    .for_profile(self.local.clone())
                    .map_err(|error| error.to_string())
            });
        (DialConfig { network }, self.flags)
    }

    /// Records an authenticated connection without network IO.
    /// # Errors
    /// Refuses a connection belonging to another local identity or an invalid session transition.
    pub fn adopt(&mut self, dialled: Dialled, now_ms: u64) -> Result<PeerLink, HostError> {
        self.adopt_with_events(dialled, now_ms)
            .map(|(link, _)| link)
    }

    /// Records the authenticated connection and returns the resulting lifecycle events.
    /// # Errors
    /// Refuses mismatched local identities and failed session transitions.
    pub fn adopt_with_events(
        &mut self,
        dialled: Dialled,
        now_ms: u64,
    ) -> Result<(PeerLink, Vec<RegistryEvent>), HostError> {
        let Dialled {
            mut link,
            negotiated,
            address,
        } = dialled;
        if link.local() != self.identity.device_id || link.peer() != negotiated.device_id {
            return Err(HostError::Authentication {
                why: "connection identities do not match this host".to_owned(),
            });
        }
        let (key, mut events) = self.sessions.open(
            SessionId::new(),
            negotiated.device_id,
            negotiated.platform,
            LinkToken::from_bytes([0; LinkToken::LEN]),
            now_ms,
        );
        let ready = self
            .sessions
            .agree(key, negotiated.agreed, now_ms)
            .map_err(|error| HostError::Bind {
                address,
                why: error.to_string(),
            })?;
        events.extend(ready);
        self.count_link_opened();
        self.discovery.handshaked(
            negotiated.device_id,
            address,
            Some(&negotiated.display_name),
            millis_reading(now_ms),
        );
        if let Some(metrics) = &self.metrics {
            link = link.with_metrics(Arc::clone(metrics));
        }
        Ok((link, events))
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
        peer: DeviceId,
        now_ms: u64,
    ) -> Result<PeerLink, HostError> {
        let (parts, flags) = self.dialling_parts();
        let dialled = dial_peer(&parts, flags, address, peer, now_ms)?;
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
                stream
                    .set_nonblocking(false)
                    .map_err(|error| HostError::Bind {
                        address: listener
                            .local_addr()
                            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
                        why: format!("the connection could not be made blocking: {error}"),
                    })?;
                Ok(Some(stream))
            }
            // Nothing waiting. Not a failure: the caller loops and asks again.
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(HostError::Bind {
                address: listener
                    .local_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
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
        listener
            .set_nonblocking(true)
            .map_err(|error| HostError::Bind {
                address: listener
                    .local_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
                why: error.to_string(),
            })
    }

    /// Authenticates and records an accepted connection; callers holding a host mutex must use the split API.
    /// # Errors
    /// Refuses uninitialized credentials, unapproved peers and failed authentication.
    pub fn complete_handshake(
        &mut self,
        stream: TcpStream,
        now_ms: u64,
    ) -> Result<(PeerLink, Vec<RegistryEvent>), HostError> {
        let (parts, flags) = self.dialling_parts();
        let accepted = parts.accept_stream(stream, flags, now_ms)?;
        self.adopt_with_events(accepted, now_ms)
    }

    /// Accepts and authenticates one connection on an owned host.
    /// # Errors
    /// Refuses an absent listener, failed IO and failed authentication.
    pub fn accept(&mut self, now_ms: u64) -> Result<(PeerLink, Vec<RegistryEvent>), HostError> {
        let listener = self.listener.as_ref().ok_or_else(|| HostError::Bind {
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            why: "this host is not listening".to_owned(),
        })?;
        let (stream, _) = listener.accept().map_err(|error| HostError::Bind {
            address: listener
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
            why: error.to_string(),
        })?;
        self.complete_handshake(stream, now_ms)
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
        // ★ `frames_sent_total{event}` is recorded by the link, not here. A host only sees the frames a caller routes
        // through it, while a dialled link writes offers and pairing requests straight to the socket — the link is the one
        // object every frame passes, so it is where the event counter lives. Counting here as well would double every
        // routed message.
        Ok(())
    }
}

impl Dialled {
    /// Returns the authenticated, generation-bound link without exposing its socket or changing its identities.
    #[must_use]
    pub fn into_link(self) -> PeerLink {
        self.link
    }
}
