//! Restricted first-pairing consent over pinned TLS 1.3 identities.
//!
//! Both parties must obtain the other's full certificate over a trusted out-of-band path, such as
//! scanning a QR code displayed by the intended device. Discovery or receiving an invitation over
//! the network does not approve it. Parsing only validates data; host UI must establish its provenance.
//! Mutual TLS proves possession of those exact keys. RFC 9266 binds user consent to this one handshake.
//!
//! This ALPN is separate from business connections. No raw socket or general Read/Write interface
//! is exposed. User consent and durable receipts form one pairing mechanism instance. The connection
//! closes after that instance completes or fails, as required by RFC 9266 section 4.1. A shared service
//! persists consent before sending its receipt and rechecks cancellation/revocation before granting
//! business permission on a separate authenticated connection.

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
    /// Local persistence or its commit recheck failed; no durable receipt is issued.
    #[error("local pairing persistence was refused")]
    LocalPersistenceRefused,
    /// The peer could not durably record this pairing.
    #[error("peer pairing persistence was refused")]
    PeerPersistenceRefused,
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

    /// Local credential used by this channel, for checking the enrollment before creating a task.
    #[must_use]
    pub const fn local_identity(&self) -> &PeerIdentity {
        &self.local
    }

    /// Correlates the local task with this exact TLS handshake before the user answers.
    ///
    /// # Errors
    /// Refuses an unavailable TLS exporter; never derives a substitute from device identifiers.
    pub fn session_binding(&self) -> Result<[u8; 32], PairingError> {
        self.stream.channel_binding().map_err(PairingError::from)
    }

    /// Time left for this entire pairing instance, including durable completion.
    #[must_use]
    pub fn remaining_window(&self) -> Option<Duration> {
        self.expires
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    }

    /// Exchanges explicit local user consent and advances into the persistence stage.
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
    ) -> Result<ConsentExchange, PairingError> {
        let remaining = self
            .expires
            .checked_duration_since(Instant::now())
            .ok_or(AuthenticationError::TimedOut)?;
        self.stream.start_budget(timeout.min(remaining))?;
        let binding = self.stream.channel_binding()?;
        confirmation::exchange(
            &mut self.stream,
            &self.local,
            binding,
            approved,
            confirmation::Stage::Consent,
        )?;
        self.stream.check_budget()?;
        if Instant::now() >= self.expires {
            return Err(AuthenticationError::TimedOut.into());
        }
        let peer = self.stream.peer_identity().clone();
        Ok(ConsentExchange {
            stream: self.stream,
            consent: MutualConsent {
                local: self.local,
                peer,
                binding,
            },
            expires: self.expires,
        })
    }
}

/// Both users consented; the connection remains restricted while the service persists that fact.
/// Dropping this value aborts the pairing and closes its only socket.
pub struct ConsentExchange {
    stream: AuthenticatedStream,
    consent: MutualConsent,
    expires: Instant,
}

impl ConsentExchange {
    #[cfg(test)]
    pub(in crate::authentication) fn expire_for_test(&mut self) {
        self.expires = Instant::now();
    }

    /// Evidence the service must durably store before claiming persistence success.
    #[must_use]
    pub const fn consent(&self) -> &MutualConsent {
        &self.consent
    }

    /// Sends a durable receipt only after the caller has committed consent and rechecked its task.
    ///
    /// `stored = false` informs the peer of local failure without waiting. Success requires the
    /// peer's matching receipt for the same stage, identities and original TLS session. The connection
    /// closes on every outcome. The caller must still atomically activate the unchanged local task.
    ///
    /// # Errors
    /// Refuses failed persistence, expiry, wrong or missing receipts and failed transport.
    pub fn complete(
        mut self,
        stored: bool,
        timeout: Duration,
    ) -> Result<DurableConfirmation, PairingError> {
        let remaining = self
            .expires
            .checked_duration_since(Instant::now())
            .ok_or(AuthenticationError::TimedOut)?;
        self.stream.start_budget(timeout.min(remaining))?;
        confirmation::exchange(
            &mut self.stream,
            &self.consent.local,
            self.consent.binding,
            stored,
            confirmation::Stage::Stored,
        )?;
        self.stream.check_budget()?;
        if Instant::now() >= self.expires {
            return Err(AuthenticationError::TimedOut.into());
        }
        Ok(DurableConfirmation {
            consent: self.consent,
        })
    }
}

/// Both authenticated peers reported durable storage in this single pairing instance.
/// Private construction prevents a service from mistaking an ordinary consent record for this receipt.
pub struct DurableConfirmation {
    consent: MutualConsent,
}

impl DurableConfirmation {
    /// Identities and session correlation validated in both stages.
    #[must_use]
    pub const fn consent(&self) -> &MutualConsent {
        &self.consent
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
