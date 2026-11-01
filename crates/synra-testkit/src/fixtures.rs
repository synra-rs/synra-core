//! A real file database for tests that need two devices talking over real sockets.
//!
//! # What this used to be, and why it is smaller now
//!
//! It carried generated TLS credentials, per-identity key caching and a pre-approved peer, because a business connection
//! could only be opened between two devices whose certificates each side had already stored. Transport encryption is gone
//! ([ADR-025](../../../design-docs/20-adr.md)), so the only thing a socket test needs from a fixture is a migrated database
//! file and a clock.
use std::sync::Arc;

use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;
use synra_store::sqlite::{DbError, SynraDb};
use synra_store::IdentityRow;

/// A fixture could not be prepared.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The database refused to open, migrate or record the local identity.
    #[error(transparent)]
    Database(#[from] DbError),
    /// The temporary directory could not be created.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An invalid test clock or identity was refused.
    #[error("fixture claim refused")]
    Refused,
}

/// An independently owned file database for one test device.
pub struct NetworkFixture {
    database: SynraDb,
    /// A separate connection to the same real file, for code that expects its own handle.
    pub shared_db: Arc<Mutex<SynraDb>>,
    /// Epoch milliseconds at fixture creation, suitable for real socket tests.
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


    /// Creates a migrated file database with a local identity and nothing else.
    /// # Errors
    /// Refuses failed migration or a refused local identity.
    pub fn unpaired(local: DeviceId, name: &str) -> Result<Self, FixtureError> {
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
        )
        .map_err(|_| FixtureError::Refused)?;
        database.create_identity_if_absent(&identity)?;
        let shared_db = Arc::new(Mutex::new(SynraDb::open(&path)?));
        Ok(Self {
            database,
            shared_db,
            now_ms: u64::try_from(now_ms).map_err(|_| FixtureError::Refused)?,
            _directory: directory,
        })
    }
}
