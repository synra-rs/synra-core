use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, Connection, ServerConfig};

use super::credentials::{roots, server_name};
use super::{ALPN, AuthenticationError, DeviceCredentials, MAX_APPROVED_PEERS, MAX_HANDSHAKE_TIME};
use super::{PeerIdentity, TLS_BUFFER_BYTES, transport};

pub(super) fn client(
    local: &DeviceCredentials,
    peer: &PeerIdentity,
) -> Result<ClientConfig, AuthenticationError> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(rejected)?
            .with_root_certificates(roots(std::iter::once(peer.certificate.clone()))?)
            .with_client_auth_cert(
                vec![local.public_identity().certificate.clone()],
                local.key(),
            )
            .map_err(rejected)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

pub(super) fn server(
    local: &DeviceCredentials,
    peers: &[PeerIdentity],
) -> Result<ServerConfig, AuthenticationError> {
    validate_peers(peers)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(peers.iter().map(|peer| peer.certificate.clone()))?),
        Arc::clone(&provider),
    )
    .build()
    .map_err(rejected)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(rejected)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![local.public_identity().certificate.clone()],
            local.key(),
        )
        .map_err(rejected)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(config)
}

fn validate_peers(peers: &[PeerIdentity]) -> Result<(), AuthenticationError> {
    if peers.is_empty() || peers.len() > MAX_APPROVED_PEERS {
        return Err(AuthenticationError::InvalidPeerList(
            "peer count outside limit".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut certificates = BTreeSet::new();
    for peer in peers {
        if !ids.insert(peer.device_id()) || !certificates.insert(peer.fingerprint()) {
            return Err(AuthenticationError::InvalidPeerList(
                "duplicate device id or credential".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn connect(
    local: &DeviceCredentials,
    peer: &PeerIdentity,
) -> Result<Connection, AuthenticationError> {
    rustls::ClientConnection::new(
        Arc::new(client(local, peer)?),
        server_name(peer.device_id())?,
    )
    .map(Connection::Client)
    .map_err(rejected)
}

pub(super) fn accept(
    local: &DeviceCredentials,
    peers: &[PeerIdentity],
) -> Result<Connection, AuthenticationError> {
    rustls::ServerConnection::new(Arc::new(server(local, peers)?))
        .map(Connection::Server)
        .map_err(rejected)
}

pub(super) fn complete(
    connection: &mut Connection,
    socket: &mut DeadlineSocket,
    peers: &[PeerIdentity],
) -> Result<PeerIdentity, AuthenticationError> {
    connection.set_buffer_limit(Some(TLS_BUFFER_BYTES));
    connection
        .complete_io(socket)
        .map_err(|error| transport(&error))?;
    socket.remaining()?;
    if connection.is_handshaking() || connection.alpn_protocol() != Some(ALPN) {
        return Err(AuthenticationError::Rejected(
            "incomplete handshake or missing synra ALPN".to_owned(),
        ));
    }
    // Trust anchors may authorize signed descendants. Device approval authorizes only the exact
    // presented leaf, so TLS chain validation alone is deliberately insufficient.
    let certificate = connection
        .peer_certificates()
        .and_then(|chain| chain.first());
    let peer = certificate
        .and_then(|certificate| peers.iter().find(|peer| peer.certificate == *certificate))
        .ok_or_else(|| {
            AuthenticationError::Rejected("peer certificate is not pinned".to_owned())
        })?;
    socket.finish().map_err(|error| transport(&error))?;
    Ok(peer.clone())
}

fn rejected(error: impl std::fmt::Display) -> AuthenticationError {
    AuthenticationError::Rejected(error.to_string())
}

/// Apply the remaining total budget at *every* actual socket operation, including rustls' internal
/// retries and partial writes. A per-call timeout set only before `complete_io` lets slow peers extend
/// the handshake indefinitely. The wrapper is also used by the completed stream after the deadline clears.
pub(super) struct DeadlineSocket {
    socket: TcpStream,
    deadline: Option<Instant>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl DeadlineSocket {
    pub(super) fn new(socket: TcpStream, timeout: Duration) -> Result<Self, AuthenticationError> {
        if timeout.is_zero() {
            return Err(AuthenticationError::TimedOut);
        }
        let deadline = Instant::now()
            .checked_add(timeout.min(MAX_HANDSHAKE_TIME))
            .ok_or(AuthenticationError::TimedOut)?;
        let read_timeout = socket.read_timeout().map_err(|error| transport(&error))?;
        let write_timeout = socket.write_timeout().map_err(|error| transport(&error))?;
        socket
            .set_nonblocking(false)
            .map_err(|error| transport(&error))?;
        Ok(Self {
            socket,
            deadline: Some(deadline),
            read_timeout,
            write_timeout,
        })
    }

    fn remaining(&self) -> Result<Duration, AuthenticationError> {
        self.deadline
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .filter(|remaining| !remaining.is_zero())
            .ok_or(AuthenticationError::TimedOut)
    }

    fn apply_deadline(&self) -> io::Result<()> {
        if self.deadline.is_some() {
            let remaining = self
                .remaining()
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            self.socket.set_read_timeout(Some(remaining))?;
            self.socket.set_write_timeout(Some(remaining))?;
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        self.socket.set_read_timeout(self.read_timeout)?;
        self.socket.set_write_timeout(self.write_timeout)?;
        self.deadline = None;
        Ok(())
    }

    pub(super) const fn socket(&self) -> &TcpStream {
        &self.socket
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.apply_deadline()?;
        self.socket.read(buffer)
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.apply_deadline()?;
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.apply_deadline()?;
        self.socket.flush()
    }
}
