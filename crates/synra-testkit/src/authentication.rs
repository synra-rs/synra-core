//! Real TLS credentials and a file database with explicitly preapproved trust facts for host tests.
//!
//! These fixtures never use an OS secret backend and do not prove the first-pairing protocol. Tests
//! of that protocol must drive its production consent and receipt exchange separately.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use synra_net::authentication::{AuthenticationError, DeviceCredentials, MAX_APPROVED_PEERS};
use synra_protocol::{DeviceId, RequestId};
use synra_store::sqlite::PeerTrustAttempt;
use synra_store::{DbError, IdentityRow, SynraDb};

/// A failure while preparing authenticated host test data.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// SQLite could not initialize the fixture.
    #[error(transparent)]
    Database(#[from] DbError),
    /// A test identity row was malformed.
    #[error(transparent)]
    Identity(#[from] synra_store::records::RowError),
    /// Test credentials could not be generated.
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    /// A temporary directory could not be created.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A bounded fixture claim or an invalid test clock was refused.
    #[error("authenticated fixture claim refused")]
    Refused,
}

/// Process-local credentials shared by fixtures naming the same test identity; never persisted to a keychain.
/// # Errors
/// Refuses generation failures, invalid clocks and more than 256 distinct fixture identities.
pub fn credentials_for(id: DeviceId) -> Result<Arc<DeviceCredentials>, FixtureError> {
    static KEYS: OnceLock<Mutex<HashMap<DeviceId, Arc<DeviceCredentials>>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = keys.lock().get(&id).cloned();
    if let Some(cached) = cached {
        return Ok(cached);
    }
    let now =
        u64::try_from(synra_store::sqlite::now_ms() / 1000).map_err(|_| FixtureError::Refused)?;
    let candidate = Arc::new(DeviceCredentials::generate(id, now)?);
    let mut values = keys.lock();
    if values.len() >= MAX_APPROVED_PEERS {
        return Err(FixtureError::Refused);
    }
    Ok(Arc::clone(values.entry(id).or_insert(candidate)))
}

/// An independently owned file database and its authenticated local test credential.
pub struct NetworkFixture {
    database: SynraDb,
    /// A separate connection to the same real file, used by production authorization checks.
    pub shared_db: Arc<Mutex<SynraDb>>,
    /// Test credential corresponding to the fixture's local enrollment.
    pub credentials: Arc<DeviceCredentials>,
    /// Epoch milliseconds at fixture creation, suitable for real TLS tests.
    pub now_ms: u64,
    _directory: tempfile::TempDir,
}

impl std::ops::Deref for NetworkFixture {
    type Target = SynraDb;
    fn deref(&self) -> &Self::Target {
        &self.database
    }
}

impl NetworkFixture {
    /// Root of this independently owned fixture, for a production host's data paths.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        self._directory.path()
    }

    /// Opens a separate connection to this fixture's database without replacing its identity.
    /// # Errors
    /// Returns the database open error.
    pub fn open_connection(&self) -> Result<SynraDb, DbError> {
        SynraDb::open(&self.root().join(synra_store::DB_FILE_NAME))
    }

    /// Creates a migrated file database whose local identity explicitly approves the supplied peer.
    /// # Errors
    /// Refuses invalid identities, failed migration, enrollment or grant persistence.
    pub fn new(local: DeviceId, peer: DeviceId, name: &str) -> Result<Self, FixtureError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(synra_store::DB_FILE_NAME);
        let mut database = SynraDb::open(&path)?;
        database.migrate()?;
        let now_ms = synra_store::sqlite::now_ms();
        let identity = IdentityRow::from_columns(
            Some(&local.to_string()),
            Some(name),
            Some("test"),
            Some(now_ms),
        )?;
        database.create_identity_if_absent(&identity)?;
        let credentials = credentials_for(local)?;
        let other = credentials_for(peer)?;
        if !database.claim_device_credential(
            &local.to_string(),
            credentials.public_identity().certificate_der(),
            "test-fixture",
        )? {
            return Err(FixtureError::Refused);
        }
        let marker = database.device_credential()?.ok_or(FixtureError::Refused)?;
        if !database.finish_device_credential(&marker)? {
            return Err(FixtureError::Refused);
        }
        let attempt = PeerTrustAttempt {
            request_id: RequestId::new().to_string(),
            local_id: local.to_string(),
            local_certificate: credentials.public_identity().certificate_der().to_vec(),
            peer_id: peer.to_string(),
            peer_certificate: other.public_identity().certificate_der().to_vec(),
            binding: [7; 32],
            expires_at_ms: now_ms.checked_add(60_000).ok_or(FixtureError::Refused)?,
        };
        if !database.claim_peer_trust(&attempt, now_ms, MAX_APPROVED_PEERS)?
            || !database.store_peer_consent(&attempt, now_ms)?
            || !database.activate_peer_trust(&attempt, now_ms)?
        {
            return Err(FixtureError::Refused);
        }
        let shared_db = Arc::new(Mutex::new(SynraDb::open(&path)?));
        Ok(Self {
            database,
            shared_db,
            credentials,
            now_ms: u64::try_from(now_ms).map_err(|_| FixtureError::Refused)?,
            _directory: directory,
        })
    }
}
