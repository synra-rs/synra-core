//! Authenticated business entry point: TLS, identity-bound Hello and immutable authorization per link.
//!
//! This entry point consumes sockets and never exposes the underlying stream. Retained decoder bytes
//! pass through the same authorization gate as new reads. Hosts must use this entry point instead of
//! the legacy plaintext helpers; discovery and first pairing remain separate restricted workflows.

mod stream;

use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use synra_net::authentication::{AuthenticatedStream, AuthenticationError, DeviceCredentials};
use synra_protocol::handshake::PairingState;
use synra_store::SynraDb;

use super::{Flags, HandshakeError, LocalPeer, Negotiated};
use crate::link::{LinkError, LinkStream, PeerLink};
use crate::peer_trust::{PeerApproval, TrustError, approved_peers};
use stream::AuthorizedStream;

/// Why an authenticated business link could not be established.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecurePeerError {
    /// The local profile does not match its credential, or is malformed.
    #[error("invalid authenticated local profile: {0}")]
    LocalProfile(String),
    /// Mutual TLS or its total deadline failed.
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    /// Durable approval could not be loaded.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The authenticated authorization was revoked or unavailable.
    #[error(transparent)]
    Authorization(#[from] LinkError),
    /// Application negotiation or its identity check failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
}

/// Shared business connection configuration, safe to clone outside a host mutex before network IO.
#[derive(Clone)]
pub struct AuthenticatedPeer {
    db: Arc<Mutex<SynraDb>>,
    credentials: Arc<DeviceCredentials>,
    profile: LocalPeer,
}

impl AuthenticatedPeer {
    /// Associates a validated local profile with its exact TLS credential and approval database.
    /// # Errors
    /// Refuses mismatched local device ids and invalid profiles.
    pub fn new(
        db: Arc<Mutex<SynraDb>>,
        credentials: Arc<DeviceCredentials>,
        profile: LocalPeer,
    ) -> Result<Self, SecurePeerError> {
        if profile.device_id != credentials.public_identity().device_id() {
            return Err(SecurePeerError::LocalProfile(
                "device id differs from credential".to_owned(),
            ));
        }
        profile
            .hello(synra_protocol::handshake::SessionNonce::random(), 0)
            .validate()
            .map_err(|error| SecurePeerError::LocalProfile(error.to_string()))?;
        Ok(Self {
            db,
            credentials,
            profile,
        })
    }

    /// Authenticates a connected socket, validates HelloAck against TLS and retains this approval generation.
    ///
    /// No pairing token proves identity here. TLS and Hello share a total budget clamped to HELLO_TIMEOUT.
    /// Any failure consumes and drops the socket. The resulting link rechecks each frame, including chunks.
    /// # Errors
    /// Refuses changed credentials, stale approvals, peer identities, invalid negotiation and timeouts.
    pub fn connect(
        &self,
        socket: TcpStream,
        approval: PeerApproval,
        sequence: u64,
        timeout: Duration,
    ) -> Result<(PeerLink, Negotiated), SecurePeerError> {
        let started = Instant::now();
        let budget = timeout.min(synra_protocol::limits::HELLO_TIMEOUT);
        let tls =
            AuthenticatedStream::connect(socket, &self.credentials, approval.identity(), budget)?;
        let mut stream = AuthorizedStream::new(tls, approval, Arc::clone(&self.db))?;
        stream.start_budget(budget.saturating_sub(started.elapsed()))?;
        let flags = Flags {
            timeout: Some(budget),
        };
        let (negotiated, decoder) =
            super::link::dial_stream(&mut stream, &self.profile, None, sequence, flags)?;
        if negotiated.pairing != Some(PairingState::Current) {
            return Err(LinkError::Unauthorized.into());
        }
        self.finish(stream, negotiated, decoder, flags)
    }

    /// Loads a bounded approval snapshot and authenticates an incoming socket before reading Hello.
    ///
    /// Certificate validation and all network IO run outside the database mutex. The generation selected
    /// after TLS must still be current before HelloAck and before the resulting link is returned.
    /// # Errors
    /// Refuses absent or changed approvals, TLS failures, spoofed Hello identities and invalid negotiation.
    pub fn accept(
        &self,
        socket: TcpStream,
        sequence: u64,
        now_seconds: u64,
        timeout: Duration,
    ) -> Result<(PeerLink, Negotiated), SecurePeerError> {
        let started = Instant::now();
        let budget = timeout.min(synra_protocol::limits::HELLO_TIMEOUT);
        let approvals = approved_peers(&self.db, &self.credentials, now_seconds)?;
        let pins = approvals
            .iter()
            .map(|approval| approval.identity().clone())
            .collect::<Vec<_>>();
        let tls = AuthenticatedStream::accept(
            socket,
            &self.credentials,
            &pins,
            budget.saturating_sub(started.elapsed()),
        )?;
        let approval = approvals
            .into_iter()
            .find(|approval| approval.identity() == tls.peer_identity())
            .ok_or(LinkError::Unauthorized)?;
        let mut stream = AuthorizedStream::new(tls, approval, Arc::clone(&self.db))?;
        stream.start_budget(budget.saturating_sub(started.elapsed()))?;
        let flags = Flags {
            timeout: Some(budget),
        };
        let (negotiated, decoder) =
            super::link::accept_on(&mut stream, &self.profile, sequence, flags, |_, _| {
                PairingState::Current
            })?;
        self.finish(stream, negotiated, decoder, flags)
    }

    fn finish(
        &self,
        mut stream: AuthorizedStream,
        negotiated: Negotiated,
        decoder: synra_protocol::frame::FrameDecoder,
        flags: Flags,
    ) -> Result<(PeerLink, Negotiated), SecurePeerError> {
        stream.authorize(self.profile.device_id, negotiated.device_id)?;
        if !negotiated.is_usable() {
            return Err(HandshakeError::Refused {
                reason: "required features are unavailable".to_owned(),
            }
            .into());
        }
        stream.finish_budget()?;
        let link = PeerLink::new(
            stream,
            self.profile.device_id,
            negotiated.device_id,
            negotiated.agreed.clone(),
            flags,
        )
        .with_decoder(decoder);
        Ok((link, negotiated))
    }
}
