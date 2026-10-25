use parking_lot::Mutex;
use synra_net::authentication::pairing::MutualConsent;
use synra_net::authentication::{AuthenticatedStream, DeviceCredentials, PeerIdentity};
use synra_protocol::{DeviceId, RequestId};
use synra_store::SynraDb;
use synra_store::sqlite::TrustedPeerRecord;

use super::TrustError;

/// A captured approval generation; retain it with its authenticated connection and recheck each request.
pub struct PeerApproval {
    local: PeerIdentity,
    local_id: String,
    peer: PeerIdentity,
    generation: RequestId,
    record: TrustedPeerRecord,
}

impl PeerApproval {
    /// Exact peer pin for establishing an authenticated business connection.
    #[must_use]
    pub const fn identity(&self) -> &PeerIdentity {
        &self.peer
    }

    /// This approval's immutable generation; never refresh an old connection to a new generation.
    #[must_use]
    pub const fn generation(&self) -> RequestId {
        self.generation
    }

    /// Checks both actual TLS identities, the claimed sender and the current durable grant generation.
    ///
    /// Call before application Hello and each later business request. Revocation, local key change
    /// or re-pairing with even the same peer certificate denies this captured authorization.
    /// # Errors
    /// A database failure returns an error, never permission.
    pub fn allows(
        &self,
        db: &Mutex<SynraDb>,
        stream: &AuthenticatedStream,
        from: DeviceId,
    ) -> Result<bool, TrustError> {
        if from != self.peer.device_id()
            || stream.peer_identity() != &self.peer
            || stream.local_identity() != &self.local
        {
            return Ok(false);
        }
        db.lock()
            .peer_trust_current(&self.local_id, self.local.certificate_der(), &self.record)
            .map_err(|error| TrustError::Database(error.to_string()))
    }
}

/// Loads the current enrolled local identity's durable approvals, validating peer certificates outside the DB lock.
/// # Errors
/// Refuses corrupt, expired or inconsistent peer records and database failures.
pub fn approved_peers(
    db: &Mutex<SynraDb>,
    local: &DeviceCredentials,
    now_seconds: u64,
) -> Result<Vec<PeerApproval>, TrustError> {
    let local = local.public_identity();
    let local_id = local.device_id().to_string();
    let records = db
        .lock()
        .trusted_peer_records(&local_id, local.certificate_der())
        .map_err(|error| TrustError::Database(error.to_string()))?;
    records
        .into_iter()
        .map(|record| {
            let id = record
                .peer_id
                .parse()
                .map_err(|_| TrustError::InvalidRecord("invalid peer id".to_owned()))?;
            let peer = PeerIdentity::from_certificate(id, &record.certificate, now_seconds)
                .map_err(|error| TrustError::InvalidRecord(error.to_string()))?;
            from_record(local, peer, record)
        })
        .collect()
}

pub(super) fn from_consent(
    consent: &MutualConsent,
    generation: &str,
) -> Result<PeerApproval, TrustError> {
    let peer = consent.peer_identity();
    let record = TrustedPeerRecord {
        peer_id: peer.device_id().to_string(),
        certificate: peer.certificate_der().to_vec(),
        generation: generation.to_owned(),
    };
    from_record(consent.local_identity(), peer.clone(), record)
}

fn from_record(
    local: &PeerIdentity,
    peer: PeerIdentity,
    record: TrustedPeerRecord,
) -> Result<PeerApproval, TrustError> {
    let generation = record
        .generation
        .parse()
        .map_err(|_| TrustError::InvalidRecord("invalid approval generation".to_owned()))?;
    Ok(PeerApproval {
        local: local.clone(),
        local_id: local.device_id().to_string(),
        peer,
        generation,
        record,
    })
}
