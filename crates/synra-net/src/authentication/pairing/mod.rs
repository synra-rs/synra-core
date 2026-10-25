//! Restricted first-pairing consent over pinned TLS 1.3 identities.
//!
//! Both parties must obtain the other's full certificate over a trusted out-of-band path, such as
//! scanning a QR code displayed by the intended device. Discovery or receiving an invitation over
//! the network does not approve it. Parsing only validates data; host UI must establish its provenance.
//! Mutual TLS proves possession of those exact keys. RFC 9266 binds user consent to this one handshake.
//!
//! This ALPN is separate from business connections. No raw socket or general Read/Write interface
//! is exposed. Consent consumes and closes the connection, including failures and cancellation;
//! RFC 9266 section 4.1 requires closing it after the authentication mechanism instance concludes.
//! A [`MutualConsent`] is preliminary evidence, not a pairing grant: the shared service must still
//! persist both approvals, recheck cancellation/revocation and acknowledge durable completion before
//! permitting business traffic on a separate authenticated connection.

mod confirmation;
mod invitation;

use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::{AuthenticatedStream, AuthenticationError, DeviceCredentials, PeerIdentity};

pub use invitation::{MAX_INVITATION_BYTES, decode_invitation, encode_invitation};

/// Maximum consent window after the TLS handshake, including time waiting for the local user.
pub const MAX_CONSENT_TIME: Duration = Duration::from_secs(60);
/// Maximum consent JSON payload; checked before allocating its receive buffer.
pub const MAX_CONSENT_BYTES: usize = 1024;

const PAIRING_ALPN: &[u8] = b"synra/pairing/1";

/// Why an out-of-band invitation or a restricted consent exchange failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    /// The invitation is unsupported, too large or malformed.
    #[error("invalid pairing invitation: {0}")]
    InvalidInvitation(&'static str),
    /// Credentials, TLS, socket IO or the total time budget failed.
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    /// A bounded consent record did not match this session and its identities.
    #[error("pairing consent rejected: {0}")]
    Rejected(&'static str),
    /// The local user declined; the channel has been consumed and closed.
    #[error("local user declined pairing")]
    LocalDeclined,
    /// The authenticated peer declined; no consent evidence is produced.
    #[error("peer declined pairing")]
    PeerDeclined,
}

/// An ephemeral, single-use channel for one pair of out-of-band approved certificates.
///
/// The owner must discard it when its UI task is cancelled or expires. Calling [`Self::confirm`]
/// after expiry fails even if the socket is still connected; no evidence can be issued late.
pub struct PairingChannel {
    stream: AuthenticatedStream,
    local: PeerIdentity,
    expires: Instant,
}

impl PairingChannel {
    /// Connects using a peer certificate already verified through the host's out-of-band UI flow.
    ///
    /// # Errors
    /// Refuses self-pairing, failed mutual TLS, changed certificates, wrong ALPN and handshake timeout.
    pub fn connect(
        socket: TcpStream,
        local: &DeviceCredentials,
        peer: &PeerIdentity,
        timeout: Duration,
    ) -> Result<Self, PairingError> {
        distinct(local, peer)?;
        let stream = AuthenticatedStream::connect_for(socket, local, peer, timeout, PAIRING_ALPN)?;
        Self::new(stream, local.public_identity().clone())
    }

    /// Accepts only the one certificate approved for this local pairing task.
    ///
    /// # Errors
    /// Matches [`Self::connect`]; arbitrary discovery peers and anonymous clients are never admitted.
    pub fn accept(
        socket: TcpStream,
        local: &DeviceCredentials,
        peer: &PeerIdentity,
        timeout: Duration,
    ) -> Result<Self, PairingError> {
        distinct(local, peer)?;
        let stream = AuthenticatedStream::accept_for(
            socket,
            local,
            std::slice::from_ref(peer),
            timeout,
            PAIRING_ALPN,
        )?;
        Self::new(stream, local.public_identity().clone())
    }

    fn new(stream: AuthenticatedStream, local: PeerIdentity) -> Result<Self, PairingError> {
        let expires = Instant::now()
            .checked_add(MAX_CONSENT_TIME)
            .ok_or(AuthenticationError::TimedOut)?;
        Ok(Self {
            stream,
            local,
            expires,
        })
    }

    #[cfg(test)]
    pub(in crate::authentication) fn expire_for_test(&mut self) {
        self.expires = Instant::now();
    }

    /// The exact authenticated identity to display in the local approval prompt.
    #[must_use]
    pub const fn peer_identity(&self) -> &PeerIdentity {
        self.stream.peer_identity()
    }

    /// Exchanges explicit local user consent and consumes this connection in every outcome.
    ///
    /// A decline is sent without waiting for the remote user. Positive consent requires the peer's
    /// matching TLS exporter, sender and target ids. `timeout` is clamped to the remaining UI window,
    /// and the budget is reapplied before every actual socket IO, including partial TLS records.
    /// Neither a successful exchange nor parsing an invitation grants business permission.
    ///
    /// # Errors
    /// Returns an error on decline, expiry, changed session, invalid records or failed transport.
    pub fn confirm(
        mut self,
        approved: bool,
        timeout: Duration,
    ) -> Result<MutualConsent, PairingError> {
        let remaining = self
            .expires
            .checked_duration_since(Instant::now())
            .ok_or(AuthenticationError::TimedOut)?;
        self.stream.start_budget(timeout.min(remaining))?;
        let binding = self.stream.channel_binding()?;
        confirmation::exchange(&mut self.stream, &self.local, binding, approved)?;
        self.stream.check_budget()?;
        if Instant::now() >= self.expires {
            return Err(AuthenticationError::TimedOut.into());
        }
        let peer = self.stream.peer_identity().clone();
        // `self` drops the only socket. There is no conversion into a business stream.
        Ok(MutualConsent {
            local: self.local,
            peer,
            binding,
        })
    }
}

/// Both users consented on one pinned TLS connection; durable pairing is still required.
///
/// Private construction and no Clone/Deserialize prevent callers from fabricating or duplicating
/// this evidence. It contains public identities and session correlation, never either private key.
pub struct MutualConsent {
    local: PeerIdentity,
    peer: PeerIdentity,
    binding: [u8; 32],
}

impl MutualConsent {
    /// Local identity used in the authenticated TLS handshake.
    #[must_use]
    pub const fn local_identity(&self) -> &PeerIdentity {
        &self.local
    }

    /// Out-of-band approved identity that authenticated and explicitly consented.
    #[must_use]
    pub const fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    /// RFC 9266 channel binding for correlating the eventual durable pairing task.
    #[must_use]
    pub const fn session_binding(&self) -> &[u8; 32] {
        &self.binding
    }
}

fn distinct(local: &DeviceCredentials, peer: &PeerIdentity) -> Result<(), PairingError> {
    if local.public_identity().device_id() == peer.device_id() {
        return Err(PairingError::Rejected(
            "cannot pair with the local device id",
        ));
    }
    Ok(())
}
