use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, Connection, ServerConfig};
use synra_protocol::DeviceId;

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
    alpn: &[u8],
) -> Result<Connection, AuthenticationError> {
    let mut config = client(local, peer)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    rustls::ClientConnection::new(Arc::new(config), server_name(peer.device_id())?)
        .map(Connection::Client)
        .map_err(rejected)
}

pub(super) fn accept(
    local: &DeviceCredentials,
    peers: &[PeerIdentity],
    alpn: &[u8],
) -> Result<Connection, AuthenticationError> {
    let mut config = server(local, peers)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    rustls::ServerConnection::new(Arc::new(config))
        .map(Connection::Server)
        .map_err(rejected)
}

pub(super) fn complete(
    connection: &mut Connection,
    socket: &mut DeadlineSocket,
    peers: &[PeerIdentity],
    alpn: &[u8],
) -> Result<PeerIdentity, AuthenticationError> {
    connection.set_buffer_limit(Some(TLS_BUFFER_BYTES));
    connection
        .complete_io(socket)
        .map_err(|error| transport(&error))?;
    socket.remaining()?;
    if connection.is_handshaking() || connection.alpn_protocol() != Some(alpn) {
        return Err(AuthenticationError::Rejected(
            "incomplete handshake or unexpected ALPN".to_owned(),
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

/// Accepts whatever certificate the other side presents, and reports the one it saw.
///
/// # Why first pairing cannot pin, and why that is not a hole
///
/// Every other connection on this transport names its peer up front and refuses a different certificate. First pairing is
/// the one exchange with no name yet: two devices have never met, so neither holds the other's certificate, and pinning
/// is exactly what the exchange produces. Demanding a pin *before* it is circular — which is why the old flow made a
/// person carry the string between two screens.
///
/// What replaces the pin is the six digits both screens show. They are derived from the two device ids, so the digits
/// agree only when both sides are talking about the same two devices. A person compares them and answers; both
/// certificates are recorded after that answer, and every later connection pins them the usual way. The trust decision
/// still happens in front of a person — they just no longer act as the transport.
///
/// This type therefore verifies *nothing* by design. It exists so `complete_unverified` can read the certificate that
/// was presented; it must never be used on a connection that already has an approved peer.
#[derive(Debug)]
struct TrustOnFirstUse {
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Always empty: this verifier has no authority to advertise, because it does not consult one.
    hints: Vec<rustls::DistinguishedName>,
}

impl TrustOnFirstUse {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider, hints: Vec::new() }
    }
}

impl rustls::client::danger::ServerCertVerifier for TrustOnFirstUse {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // The signature check is *not* what is being waived. It only says the peer holds the key for the certificate it
        // showed, which this side wants to be true regardless of whether it has seen that certificate before.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for TrustOnFirstUse {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Opens a first-pairing connection to a device whose certificate this side has never seen.
pub(super) fn connect_unverified(
    local: &DeviceCredentials,
    alpn: &[u8],
    peer: DeviceId,
) -> Result<Connection, AuthenticationError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(rejected)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustOnFirstUse::new(provider)))
        .with_client_auth_cert(
            vec![local.public_identity().certificate.clone()],
            local.key(),
        )
        .map_err(rejected)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    rustls::ClientConnection::new(Arc::new(config), server_name(peer)?)
        .map(Connection::Client)
        .map_err(rejected)
}

/// Answers a first-pairing connection from a device whose certificate this side has never seen.
pub(super) fn accept_unverified(
    local: &DeviceCredentials,
    alpn: &[u8],
) -> Result<Connection, AuthenticationError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(rejected)?
        .with_client_cert_verifier(Arc::new(TrustOnFirstUse::new(provider)))
        .with_single_cert(
            vec![local.public_identity().certificate.clone()],
            local.key(),
        )
        .map_err(rejected)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    rustls::ServerConnection::new(Arc::new(config))
        .map(Connection::Server)
        .map_err(rejected)
}

/// Finishes an unverified handshake and returns the certificate the peer presented.
///
/// The caller turns that into a [`PeerIdentity`] once the first message says which device sent it — the device id is not
/// read out of the certificate here, because a first pairing must not trust a name the certificate merely claims.
pub(super) fn complete_unverified(
    connection: &mut Connection,
    socket: &mut DeadlineSocket,
    alpn: &[u8],
) -> Result<Vec<u8>, AuthenticationError> {
    connection.set_buffer_limit(Some(TLS_BUFFER_BYTES));
    connection
        .complete_io(socket)
        .map_err(|error| transport(&error))?;
    socket.remaining()?;
    if connection.is_handshaking() || connection.alpn_protocol() != Some(alpn) {
        return Err(AuthenticationError::Rejected(
            "incomplete handshake or unexpected ALPN".to_owned(),
        ));
    }
    let certificate = connection
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or_else(|| {
            AuthenticationError::Rejected("peer presented no certificate".to_owned())
        })?;
    let bytes = certificate.as_ref().to_vec();
    socket.finish().map_err(|error| transport(&error))?;
    Ok(bytes)
}

fn rejected(error: impl std::fmt::Display) -> AuthenticationError {
    AuthenticationError::Rejected(error.to_string())
}

/// Apply the remaining total budget at *every* actual socket operation, including rustls' internal
/// retries and partial writes. A per-call timeout set only before `complete_io` lets slow peers extend
/// the handshake indefinitely. The wrapper is also used by the completed stream after the deadline clears.
pub(super) struct DeadlineSocket {
    socket: TcpStream,
    deadline: Cell<Option<Instant>>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    cancelled: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl DeadlineSocket {
    pub(super) fn new(
        socket: TcpStream,
        timeout: Duration,
        cancelled: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<Self, AuthenticationError> {
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
            deadline: Cell::new(Some(deadline)),
            read_timeout,
            write_timeout,
            cancelled,
        })
    }

    pub(super) fn remaining(&self) -> Result<Duration, AuthenticationError> {
        self.deadline
            .get()
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .filter(|remaining| !remaining.is_zero())
            .ok_or(AuthenticationError::TimedOut)
    }

    fn apply_deadline(&self) -> io::Result<()> {
        if self
            .cancelled
            .as_ref()
            .is_some_and(|signal| signal.load(std::sync::atomic::Ordering::Acquire))
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "pairing operation cancelled",
            ));
        }
        if self.deadline.get().is_some() {
            let mut remaining = self
                .remaining()
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            if self.cancelled.is_some() {
                remaining = remaining.min(Duration::from_millis(100));
            }
            self.socket.set_read_timeout(Some(remaining))?;
            self.socket.set_write_timeout(Some(remaining))?;
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> io::Result<()> {
        self.socket.set_read_timeout(self.read_timeout)?;
        self.socket.set_write_timeout(self.write_timeout)?;
        self.deadline.set(None);
        Ok(())
    }

    pub(super) const fn socket(&self) -> &TcpStream {
        &self.socket
    }

    pub(super) fn start_budget(&self, timeout: Duration) -> Result<(), AuthenticationError> {
        if timeout.is_zero() {
            return Err(AuthenticationError::TimedOut);
        }
        self.deadline.set(Some(
            Instant::now()
                .checked_add(timeout)
                .ok_or(AuthenticationError::TimedOut)?,
        ));
        Ok(())
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.apply_deadline()?;
            match self.socket.read(buffer) {
                Err(error)
                    if self.cancelled.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.apply_deadline()?;
            match self.socket.write(buffer) {
                Err(error)
                    if self.cancelled.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.apply_deadline()?;
        self.socket.flush()
    }
}
