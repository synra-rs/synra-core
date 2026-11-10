//! Opens database connections and validates the schema on startup.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::db::{PRAGMAS, latest_version};

use super::{DbError, SynraDb};

impl SynraDb {
    /// Whether this connection names a persistent file rather than temporary or in-memory storage.
    #[must_use]
    pub fn is_file_backed(&self) -> bool {
        self.connection.path().is_some_and(|path| !path.is_empty())
    }

    /// Opens a database file, creating it if it is absent.
    ///
    /// # Errors
    ///
    /// [`DbError::Open`] when the file cannot be opened, and [`DbError::FromTheFuture`] when its schema is newer than
    /// this build understands.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        // The flags are explicit rather than left to the default, because `create` and `read_write` together are what
        // "the kernel owns this file" means — and a connection opened read-only would fail every write with a message
        // about a locked database.
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| DbError::Open {
            path: path.to_path_buf(),
            why: error.to_string(),
        })?;

        let db = Self {
            connection,
            write_observer: None,
        };
        db.apply_pragmas()?;
        db.refuse_a_future_schema()?;
        Ok(db)
    }

    /// Opens an existing database **without** the right to write it.
    ///
    /// # Why this exists
    ///
    /// Because restoring a backup has to inspect the file it is about to copy, and inspecting it with the ordinary open
    /// would apply the pragmas — `journal_mode = WAL` is a write, and it leaves `-wal`/`-shm` beside the backup. A
    /// recovery path that modifies the file it is recovering from is not a recovery path.
    ///
    /// The pragmas are therefore **not** applied here: this connection is for reading the schema version and running the
    /// integrity check, and it is dropped before the file is copied.
    ///
    /// # Errors
    ///
    /// [`DbError::Open`] when the file cannot be opened read-only, and [`DbError::FromTheFuture`] when its schema is newer
    /// than this build understands.
    pub fn open_read_only(path: &Path) -> Result<Self, DbError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| DbError::Open {
            path: path.to_path_buf(),
            why: error.to_string(),
        })?;
        let db = Self {
            connection,
            write_observer: None,
        };
        db.refuse_a_future_schema()?;
        Ok(db)
    }

    /// Opens a database with no file, for a test or a diagnostic that must not touch the disk.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::open`], minus the file.
    pub fn open_in_memory() -> Result<Self, DbError> {
        let connection = Connection::open_in_memory().map_err(|error| DbError::Open {
            path: std::path::PathBuf::from(":memory:"),
            why: error.to_string(),
        })?;
        let db = Self {
            connection,
            write_observer: None,
        };
        db.apply_pragmas()?;
        Ok(db)
    }

    /// Applies the pragmas the rest of the system assumes.
    fn apply_pragmas(&self) -> Result<(), DbError> {
        for (name, value) in PRAGMAS {
            self.connection
                .execute_batch(&format!("PRAGMA {name} = {value}"))
                .map_err(|error| DbError::Statement {
                    why: format!("PRAGMA {name} = {value}: {error}"),
                })?;
        }
        Ok(())
    }

    /// Refuses a database written by a newer kernel.
    pub(super) fn refuse_a_future_schema(&self) -> Result<(), DbError> {
        let Some(recorded) = self.recorded_version()? else {
            return Ok(());
        };
        if recorded > latest_version() {
            return Err(DbError::FromTheFuture {
                found: recorded,
                known: latest_version(),
            });
        }
        Ok(())
    }
}
