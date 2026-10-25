//! Bounded production pairing tasks; sockets and runtime progress never replace durable grants.
//!
//! Lock order is task slot, then database. Workers release both before TLS or consent IO, and
//! release the database before publishing terminal progress. Cancellation linearizes in the same
//! database journal as activation; a committed grant makes cancellation too late rather than false.

mod invitation;
mod worker;

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{TrustError, approved_peers};
use parking_lot::Mutex;
use synra_net::authentication::pairing::{
    MAX_CONSENT_TIME, PairingError, decode_invitation, encode_invitation,
};
use synra_net::authentication::{DeviceCredentials, PeerIdentity};
use synra_protocol::ids::{DeviceId, RequestId};
use synra_protocol::pairing::{PairingPhase, PairingSnapshot};
use synra_store::SynraDb;
use synra_store::sqlite::PeerTrustReservation;

/// A sampled wall clock for expiry presentation and durable transaction rechecks.
pub type PairingClock = dyn Fn() -> i64 + Send + Sync;

/// A refused host pairing operation; imported certificate text is never included in errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PairingServiceError {
    /// Malformed, unsupported, expired or refused out-of-band certificate.
    #[error(transparent)]
    Invitation(#[from] PairingError),
    /// Durable enrollment or authorization refused the operation.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The response invitation is malformed or uses an invalid port.
    #[error("invalid responder invitation")]
    InvalidReply,
    /// The caller must explicitly revoke the existing authorization before pairing again.
    #[error("the peer is already paired")]
    AlreadyPaired,
    /// A live or cancelling worker still owns the only slot.
    #[error("another pairing operation is still running")]
    Busy,
    /// No live task has this generation.
    #[error("the pairing task is no longer running")]
    NotRunning,
    /// Activation already committed; cancellation cannot claim to undo authorization.
    #[error("pairing already committed and cannot be cancelled")]
    TooLate,
    /// The local clock or requested timeout is unusable.
    #[error("invalid pairing time budget")]
    InvalidBudget,
    /// The total operation window elapsed.
    #[error("the pairing operation timed out")]
    TimedOut,
    /// Cancellation won before activation.
    #[error("the pairing operation was cancelled")]
    Cancelled,
    /// Socket creation, connection, shutdown or worker creation failed.
    #[error("pairing transport failed: {0}")]
    Transport(String),
}

impl PairingServiceError {
    /// The same actionable error classification for every production host.
    #[must_use]
    pub const fn code(&self) -> synra_protocol::ErrorCode {
        use synra_net::authentication::AuthenticationError;
        use synra_protocol::ErrorCode;
        match self {
            Self::InvalidReply
            | Self::InvalidBudget
            | Self::AlreadyPaired
            | Self::Busy
            | Self::TooLate
            | Self::Invitation(PairingError::InvalidInvitation(_)) => ErrorCode::InvalidArgument,
            Self::TimedOut
            | Self::Invitation(PairingError::Authentication(AuthenticationError::TimedOut)) => {
                ErrorCode::Timeout
            }
            Self::Transport(_)
            | Self::Invitation(PairingError::Authentication(AuthenticationError::Transport(_))) => {
                ErrorCode::TransportNotOpen
            }
            Self::Trust(TrustError::Database(_) | TrustError::InvalidRecord(_)) => {
                ErrorCode::Internal
            }
            _ => ErrorCode::NotPaired,
        }
    }
}

/// One live worker and at most one retained terminal snapshot for a local enrolled identity.
pub struct PairingService {
    db: Arc<Mutex<SynraDb>>,
    credentials: Arc<DeviceCredentials>,
    clock: Arc<PairingClock>,
    task: Mutex<Option<Task>>,
}

struct Task {
    snapshot: PairingSnapshot,
    deadline: Instant,
    active: bool,
    cancelled: bool,
    reservation: PeerTrustReservation,
    cancel_signal: Arc<AtomicBool>,
}

impl PairingService {
    /// Uses the same persisted identity and transaction clock as the host's authenticated network.
    #[must_use]
    pub fn new(
        db: Arc<Mutex<SynraDb>>,
        credentials: Arc<DeviceCredentials>,
        clock: Arc<PairingClock>,
    ) -> Self {
        Self {
            db,
            credentials,
            clock,
            task: Mutex::new(None),
        }
    }

    /// Public certificate invitation, to transfer only through the intended device's trusted display.
    /// Exporting or parsing it never approves a remote identity.
    /// # Errors
    /// Refuses a representation exceeding the invitation bound.
    pub fn invitation(&self) -> Result<String, PairingServiceError> {
        encode_invitation(self.credentials.public_identity()).map_err(PairingServiceError::from)
    }

    /// Explicitly approves an out-of-band invitation and opens a temporary restricted responder.
    /// The returned response must travel back through the trusted out-of-band path.
    /// # Errors
    /// Refuses invalid/self/already paired identities, occupied slots, invalid budgets or bind failures.
    pub fn listen(
        self: &Arc<Self>,
        expected: DeviceId,
        invitation: &str,
        bind: SocketAddr,
        timeout: Duration,
    ) -> Result<PairingSnapshot, PairingServiceError> {
        let peer = self.approved_invitation(expected, invitation)?;
        let listener = TcpListener::bind(bind).map_err(|error| transport(&error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| transport(&error))?;
        let port = listener
            .local_addr()
            .map_err(|error| transport(&error))?
            .port();
        let reply = invitation::reply(self.credentials.public_identity(), port)?;
        let snapshot = self.reserve(&peer, PairingPhase::Listening, Some(reply), timeout)?;
        self.spawn(
            snapshot.request_id,
            peer,
            worker::Connection::Listen(listener),
        )?;
        Ok(snapshot)
    }

    /// Explicitly approves a responder invitation and connects using its port at the chosen route.
    /// The address is a routing hint; pinned TLS must still prove the exact imported identity.
    /// # Errors
    /// Matches [`Self::listen`], plus malformed response and connection failures.
    pub fn connect(
        self: &Arc<Self>,
        expected: DeviceId,
        reply: &str,
        mut address: SocketAddr,
        timeout: Duration,
    ) -> Result<PairingSnapshot, PairingServiceError> {
        let (peer, port) = invitation::parse_reply(reply, self.now_seconds()?)?;
        self.validate_peer(expected, &peer)?;
        address.set_port(port);
        let snapshot = self.reserve(&peer, PairingPhase::Connecting, None, timeout)?;
        self.spawn(
            snapshot.request_id,
            peer,
            worker::Connection::Connect(address),
        )?;
        Ok(snapshot)
    }

    /// Snapshot of the sole current or last completed task, with no socket or private credential.
    #[must_use]
    pub fn snapshot(&self) -> Option<PairingSnapshot> {
        self.task.lock().as_ref().map(|task| task.snapshot.clone())
    }

    /// Prevents this generation from activating, then signals cancellation to bounded socket IO.
    /// A cancelling worker retains the slot until it exits; no replacement can overlap its IO.
    /// # Errors
    /// Refuses absent/terminal tasks, already committed grants, or failed cancellation persistence.
    pub fn cancel(&self, id: RequestId) -> Result<(), PairingServiceError> {
        {
            let mut slot = self.task.lock();
            let task = slot
                .as_mut()
                .filter(|task| task.active && task.snapshot.request_id == id)
                .ok_or(PairingServiceError::NotRunning)?;
            {
                let journal = &task.reservation.request_id;
                let db = self.db.lock();
                let changed = db
                    .cancel_peer_attempt(journal)
                    .map_err(|error| TrustError::Database(error.to_string()))?;
                if !changed
                    && db
                        .trusted_peer_records(
                            &self.credentials.public_identity().device_id().to_string(),
                            self.credentials.public_identity().certificate_der(),
                        )
                        .map_err(|error| TrustError::Database(error.to_string()))?
                        .iter()
                        .any(|record| &record.generation == journal)
                {
                    return Err(PairingServiceError::TooLate);
                }
            }
            task.cancelled = true;
            task.cancel_signal.store(true, Ordering::Release);
            task.snapshot.phase = PairingPhase::Cancelling;
            drop(slot);
        }
        Ok(())
    }

    fn now_seconds(&self) -> Result<u64, PairingServiceError> {
        u64::try_from((self.clock)())
            .map(|now| now / 1000)
            .map_err(|_| PairingServiceError::InvalidBudget)
    }

    fn approved_invitation(
        &self,
        expected: DeviceId,
        text: &str,
    ) -> Result<PeerIdentity, PairingServiceError> {
        let peer = decode_invitation(text, self.now_seconds()?)?;
        self.validate_peer(expected, &peer)?;
        Ok(peer)
    }

    fn validate_peer(
        &self,
        expected: DeviceId,
        peer: &PeerIdentity,
    ) -> Result<(), PairingServiceError> {
        if expected != peer.device_id() {
            return Err(
                PairingError::Rejected("invitation identity differs from selected peer").into(),
            );
        }
        if peer.device_id() == self.credentials.public_identity().device_id() {
            return Err(PairingError::Rejected("self pairing is forbidden").into());
        }
        if approved_peers(&self.db, &self.credentials, self.now_seconds()?)?
            .iter()
            .any(|approval| approval.identity().device_id() == peer.device_id())
        {
            return Err(PairingServiceError::AlreadyPaired);
        }
        Ok(())
    }

    fn reserve(
        &self,
        peer: &PeerIdentity,
        phase: PairingPhase,
        reply: Option<String>,
        timeout: Duration,
    ) -> Result<PairingSnapshot, PairingServiceError> {
        let timeout = timeout.min(MAX_CONSENT_TIME);
        if timeout.is_zero() {
            return Err(PairingServiceError::InvalidBudget);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(PairingServiceError::InvalidBudget)?;
        let now_ms = (self.clock)();
        if now_ms < 0 {
            return Err(PairingServiceError::InvalidBudget);
        }
        let expires_at_ms = now_ms
            .checked_add(
                i64::try_from(timeout.as_millis())
                    .map_err(|_| PairingServiceError::InvalidBudget)?,
            )
            .ok_or(PairingServiceError::InvalidBudget)?;
        let mut slot = self.task.lock();
        if slot.as_ref().is_some_and(|task| task.active) {
            return Err(PairingServiceError::Busy);
        }
        let snapshot = PairingSnapshot {
            request_id: RequestId::new(),
            peer_id: peer.device_id(),
            phase,
            expires_at_ms,
            reply,
            error_code: None,
            detail: None,
        };
        let reservation = PeerTrustReservation {
            request_id: snapshot.request_id.to_string(),
            local_id: self.credentials.public_identity().device_id().to_string(),
            local_certificate: self
                .credentials
                .public_identity()
                .certificate_der()
                .to_vec(),
            peer_id: peer.device_id().to_string(),
            peer_certificate: peer.certificate_der().to_vec(),
            expires_at_ms,
        };
        if !self
            .db
            .lock()
            .reserve_peer_trust(
                &reservation,
                now_ms,
                synra_net::authentication::MAX_APPROVED_PEERS,
            )
            .map_err(|error| TrustError::Database(error.to_string()))?
        {
            return Err(TrustError::ClaimRefused.into());
        }
        *slot = Some(Task {
            snapshot: snapshot.clone(),
            deadline,
            active: true,
            cancelled: false,
            reservation,
            cancel_signal: Arc::new(AtomicBool::new(false)),
        });
        drop(slot);
        Ok(snapshot)
    }

    fn spawn(
        self: &Arc<Self>,
        id: RequestId,
        peer: PeerIdentity,
        connection: worker::Connection,
    ) -> Result<(), PairingServiceError> {
        let service = Arc::clone(self);
        match std::thread::Builder::new()
            .name(format!("synra-pair-{id}"))
            .spawn(move || {
                let result = worker::run(&service, id, &peer, connection);
                service.complete(id, &result);
            }) {
            Ok(_) => Ok(()),
            Err(error) => {
                let error = transport(&error);
                self.complete(id, &Err(error));
                Err(PairingServiceError::Transport(
                    "could not start pairing worker".to_owned(),
                ))
            }
        }
    }

    fn complete(&self, id: RequestId, result: &Result<(), PairingServiceError>) {
        if result.is_err() {
            let _ = self.db.lock().cancel_peer_attempt(&id.to_string());
        }
        let mut slot = self.task.lock();
        if let Some(task) = slot.as_mut().filter(|task| task.snapshot.request_id == id) {
            task.snapshot.phase = match result {
                Ok(()) => PairingPhase::Paired,
                Err(_) if task.cancelled => PairingPhase::Cancelled,
                Err(_) if Instant::now() >= task.deadline => PairingPhase::TimedOut,
                Err(_) => PairingPhase::Failed,
            };
            if let Err(error) = result {
                task.snapshot.error_code = Some(match task.snapshot.phase {
                    PairingPhase::Cancelled => synra_protocol::ErrorCode::NotPaired,
                    PairingPhase::TimedOut => synra_protocol::ErrorCode::Timeout,
                    _ => error.code(),
                });
                task.snapshot.detail = Some(error.to_string());
            }
            task.snapshot.reply = None;
            task.active = false;
        }
    }
}

fn transport(error: &std::io::Error) -> PairingServiceError {
    PairingServiceError::Transport(error.to_string())
}
