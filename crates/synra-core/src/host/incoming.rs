use super::{Host, HostError};
use crate::link::PeerLink;
use crate::sessions::RegistryEvent;
use std::net::{SocketAddr, TcpStream};

impl Host {
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
}
