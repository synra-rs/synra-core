//! Shared pairing orchestration: bounded tasks, durable receipts and generation-bound grants.
//!
//! Runtime sockets remain owned by the task, while SQLite stores its bounded journal and independent
//! authorization facts. No database guard survives into network IO. A restart cannot promote an
//! unfinished journal row; a new live owner and a new TLS instance are required. Legacy device-list
//! metadata and bearer tokens never grant permission through this service.

mod approval;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_net::authentication::pairing::{MutualConsent, PairingChannel, PairingError};
use synra_net::authentication::{MAX_APPROVED_PEERS, PeerIdentity};
use synra_protocol::RequestId;
use synra_store::SynraDb;
use synra_store::sqlite::PeerTrustAttempt;

pub use approval::{PeerApproval, approved_peers};

/// A refused or interrupted identity-bound pairing operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// The network exchange, user decision or durable receipt failed.
    #[error(transparent)]
    Pairing(#[from] PairingError),
    /// Persistence failed; no success receipt or local grant may be inferred.
    #[error("peer trust database failed: {0}")]
    Database(String),
    /// The bounded task slot, enrollment, trust capacity or already paired target refused the claim.
    #[error("peer trust task claim was refused")]
    ClaimRefused,
    /// The task was cancelled, expired, revoked or replaced, or the local identity changed.
    #[error("peer trust task is no longer current")]
    Stale,
    /// A durable record or receipt is not a valid identity bound to this task.
    #[error("invalid peer trust record: {0}")]
    InvalidRecord(String),
}

/// The sole live pairing task, owning its restricted channel and unique journal generation.
///
/// Dropping or failing cancels only this generation. Explicit cancellation and revocation are
/// persisted immediately by their database methods; even a blocked IO worker cannot later activate it.
pub struct PairingTask {
    db: Arc<Mutex<SynraDb>>,
    attempt: PeerTrustAttempt,
    channel: Option<PairingChannel>,
    completed: bool,
}

impl PairingTask {
    /// Claims a bounded task for this exact TLS instance before showing the local user a prompt.
    /// # Errors
    /// Refuses expired channels, changed local enrollment, an occupied slot, existing trust or capacity.
    pub fn begin(
        db: Arc<Mutex<SynraDb>>,
        channel: PairingChannel,
        now_ms: i64,
    ) -> Result<Self, TrustError> {
        let remaining = channel.remaining_window().ok_or(TrustError::Stale)?;
        let remaining_ms = i64::try_from(remaining.as_millis()).map_err(|_| TrustError::Stale)?;
        let expires_at_ms = now_ms.checked_add(remaining_ms).ok_or(TrustError::Stale)?;
        let attempt = PeerTrustAttempt {
            request_id: RequestId::new().to_string(),
            local_id: channel.local_identity().device_id().to_string(),
            local_certificate: channel.local_identity().certificate_der().to_vec(),
            peer_id: channel.peer_identity().device_id().to_string(),
            peer_certificate: channel.peer_identity().certificate_der().to_vec(),
            binding: channel.session_binding()?,
            expires_at_ms,
        };
        let claimed = db
            .lock()
            .claim_peer_trust(&attempt, now_ms, MAX_APPROVED_PEERS)
            .map_err(|error| TrustError::Database(error.to_string()))?;
        if !claimed {
            return Err(TrustError::ClaimRefused);
        }
        Ok(Self {
            db,
            attempt,
            channel: Some(channel),
            completed: false,
        })
    }

    /// Opaque local task generation to use for cancellation and diagnostics.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.attempt.request_id
    }

    /// Exchanges consent, stores it, exchanges durable receipts, then atomically activates this task.
    ///
    /// `clock` is sampled again after each external phase; the caller must not pass a stale startup
    /// timestamp as the commit time. Database guards are dropped before either network exchange.
    /// # Errors
    /// Rejects every stale snapshot, declined/failed receipt, expired certificate or failed persistence.
    pub fn finish(
        mut self,
        approved: bool,
        timeout: Duration,
        clock: impl Fn() -> i64,
    ) -> Result<PeerApproval, TrustError> {
        let now_ms = clock();
        let current = self
            .db
            .lock()
            .peer_attempt_current(&self.attempt, now_ms)
            .map_err(|error| TrustError::Database(error.to_string()))?;
        if !current {
            return Err(TrustError::Stale);
        }
        let exchange = self
            .channel
            .take()
            .ok_or(TrustError::Stale)?
            .confirm(approved, timeout)?;
        let now_ms = clock();
        validate(exchange.consent(), &self.attempt, now_ms)?;
        let stored = self.db.lock().store_peer_consent(&self.attempt, now_ms);
        let failure = match stored {
            Ok(true) => None,
            Ok(false) => Some(TrustError::Stale),
            Err(error) => Some(TrustError::Database(error.to_string())),
        };
        if let Some(failure) = failure {
            let _ = exchange.complete(false, timeout);
            return Err(failure);
        }
        let receipt = exchange.complete(true, timeout)?;
        let now_ms = clock();
        validate(receipt.consent(), &self.attempt, now_ms)?;
        let approval = approval::from_consent(receipt.consent(), &self.attempt.request_id)?;
        let active = self
            .db
            .lock()
            .activate_peer_trust(&self.attempt, now_ms)
            .map_err(|error| TrustError::Database(error.to_string()))?;
        if !active {
            return Err(TrustError::Stale);
        }
        self.completed = true;
        Ok(approval)
    }
}

impl Drop for PairingTask {
    fn drop(&mut self) {
        if !self.completed {
            // A failed best-effort cleanup still cannot create a grant; the journal alone never authorizes.
            let _ = self.db.lock().cancel_peer_attempt(&self.attempt.request_id);
        }
    }
}

fn validate(
    consent: &MutualConsent,
    attempt: &PeerTrustAttempt,
    now_ms: i64,
) -> Result<(), TrustError> {
    if consent.local_identity().device_id().to_string() != attempt.local_id
        || consent.peer_identity().device_id().to_string() != attempt.peer_id
        || consent.local_identity().certificate_der() != attempt.local_certificate
        || consent.peer_identity().certificate_der() != attempt.peer_certificate
        || consent.session_binding() != &attempt.binding
        || now_ms >= attempt.expires_at_ms
    {
        return Err(TrustError::Stale);
    }
    let now_seconds = u64::try_from(now_ms).map_err(|_| TrustError::Stale)? / 1000;
    for identity in [consent.local_identity(), consent.peer_identity()] {
        PeerIdentity::from_certificate(
            identity.device_id(),
            identity.certificate_der(),
            now_seconds,
        )
        .map_err(|error| TrustError::InvalidRecord(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
