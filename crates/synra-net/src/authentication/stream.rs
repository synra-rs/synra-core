use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rustls::{ClientConnection, Connection, ServerConnection, StreamOwned};
use synra_protocol::DeviceId;

use super::handshake::{self, DeadlineSocket};
use super::{ALPN, AuthenticationError, DeviceCredentials, PeerIdentity};

enum Stream {
    Client(Box<StreamOwned<ClientConnection, DeadlineSocket>>),
    Server(Box<StreamOwned<ServerConnection, DeadlineSocket>>),
}

/// An encrypted stream whose peer proved possession of a previously approved credential.
///
/// Construction consumes the raw socket; failure drops it, and success exposes only encrypted IO.
/// The caller owns the trust snapshot and must close active sessions when approval is revoked.
pub struct AuthenticatedStream {
    stream: Stream,
    peer: PeerIdentity,
}

impl AuthenticatedStream {
    /// Authenticates an outgoing connected socket against one approved peer's exact certificate.
    ///
    /// The socket becomes blocking; existing read/write timeouts are restored after authentication.
    /// `timeout` is a total budget clamped to [`super::MAX_HANDSHAKE_TIME`].
    ///
    /// # Errors
    /// Rejects failed mutual authentication, a different certificate or protocol, IO errors and timeouts.
    pub fn connect(
        socket: TcpStream,
        local: &DeviceCredentials,
        peer: &PeerIdentity,
        timeout: Duration,
    ) -> Result<Self, AuthenticationError> {
        Self::connect_for(socket, local, peer, timeout, ALPN)
    }

    pub(super) fn connect_for(
        socket: TcpStream,
        local: &DeviceCredentials,
        peer: &PeerIdentity,
        timeout: Duration,
        alpn: &[u8],
    ) -> Result<Self, AuthenticationError> {
        let socket = DeadlineSocket::new(socket, timeout)?;
        let connection = handshake::connect(local, peer, alpn)?;
        Self::establish(socket, connection, std::slice::from_ref(peer), alpn)
    }

    /// Authenticates an incoming connected socket against a bounded snapshot of approved peers.
    ///
    /// Anonymous clients, unknown or replaced credentials and missing `synra/1` ALPN are refused.
    /// An empty trust snapshot refuses every connection; it never enables unauthenticated enrollment.
    /// Socket mode and timeout behavior match [`Self::connect`].
    ///
    /// # Errors
    /// Rejects invalid trust snapshots, failed authentication, IO errors and total handshake timeouts.
    pub fn accept(
        socket: TcpStream,
        local: &DeviceCredentials,
        peers: &[PeerIdentity],
        timeout: Duration,
    ) -> Result<Self, AuthenticationError> {
        Self::accept_for(socket, local, peers, timeout, ALPN)
    }

    pub(super) fn accept_for(
        socket: TcpStream,
        local: &DeviceCredentials,
        peers: &[PeerIdentity],
        timeout: Duration,
        alpn: &[u8],
    ) -> Result<Self, AuthenticationError> {
        let socket = DeadlineSocket::new(socket, timeout)?;
        let connection = handshake::accept(local, peers, alpn)?;
        Self::establish(socket, connection, peers, alpn)
    }

    fn establish(
        mut socket: DeadlineSocket,
        mut connection: Connection,
        peers: &[PeerIdentity],
        alpn: &[u8],
    ) -> Result<Self, AuthenticationError> {
        let peer = handshake::complete(&mut connection, &mut socket, peers, alpn)?;
        let stream = match connection {
            Connection::Client(connection) => {
                Stream::Client(Box::new(StreamOwned::new(connection, socket)))
            }
            Connection::Server(connection) => {
                Stream::Server(Box::new(StreamOwned::new(connection, socket)))
            }
        };
        Ok(Self { stream, peer })
    }

    pub(super) fn channel_binding(&self) -> Result<[u8; 32], AuthenticationError> {
        // RFC 9266 section 2: the registered label, empty context and exactly 32 bytes.
        let label = b"EXPORTER-Channel-Binding";
        let result = match &self.stream {
            Stream::Client(stream) => stream
                .conn
                .export_keying_material([0; 32], label, Some(&[])),
            Stream::Server(stream) => stream
                .conn
                .export_keying_material([0; 32], label, Some(&[])),
        };
        result.map_err(|_| {
            AuthenticationError::Rejected("TLS channel binding unavailable".to_owned())
        })
    }

    pub(super) fn start_budget(&mut self, timeout: Duration) -> Result<(), AuthenticationError> {
        match &mut self.stream {
            Stream::Client(stream) => stream.sock.start_budget(timeout),
            Stream::Server(stream) => stream.sock.start_budget(timeout),
        }
    }

    pub(super) fn check_budget(&self) -> Result<(), AuthenticationError> {
        match &self.stream {
            Stream::Client(stream) => stream.sock.remaining().map(|_| ()),
            Stream::Server(stream) => stream.sock.remaining().map(|_| ()),
        }
    }

    /// The authenticated device id; application Hello messages must match this value.
    #[must_use]
    pub const fn peer_device_id(&self) -> DeviceId {
        self.peer.device_id()
    }

    /// The exact public identity authenticated on this connection.
    #[must_use]
    pub const fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    /// Changes the application read timeout without exposing the raw socket.
    ///
    /// # Errors
    /// Returns the socket error if the timeout is invalid or cannot be applied.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket().set_read_timeout(timeout)
    }

    /// Returns the application read timeout on this stream's actual socket handle.
    ///
    /// # Errors
    /// Returns the socket error if the option cannot be read.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.socket().read_timeout()
    }

    /// Changes the application write timeout without exposing the raw socket.
    ///
    /// # Errors
    /// Returns the socket error if the timeout is invalid or cannot be applied.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket().set_write_timeout(timeout)
    }

    /// Returns the application write timeout on this stream's actual socket handle.
    ///
    /// # Errors
    /// Returns the socket error if the option cannot be read.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.socket().write_timeout()
    }

    fn socket(&self) -> &TcpStream {
        match &self.stream {
            Stream::Client(stream) => stream.sock.socket(),
            Stream::Server(stream) => stream.sock.socket(),
        }
    }
}

impl Read for AuthenticatedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.stream {
            Stream::Client(stream) => stream.read(buffer),
            Stream::Server(stream) => stream.read(buffer),
        }
    }
}

impl Write for AuthenticatedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            Stream::Client(stream) => stream.write(buffer),
            Stream::Server(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            Stream::Client(stream) => stream.flush(),
            Stream::Server(stream) => stream.flush(),
        }
    }
}
