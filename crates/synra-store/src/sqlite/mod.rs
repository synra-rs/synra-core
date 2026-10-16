//! The SQLite binding.
//!
//! # Why this exists now, when `db` deliberately does not carry a binding
//!
//! [`crate::db`] holds the migration *logic* — the ordering, the versioning, the failure behaviour — and says in its own
//! docs that it is not a binding, so that a crate holding the persistence contract can be checked without a C
//! dependency. That reasoning still holds, and this module is the other half: the part that *does* need an engine, in a
//! file of its own so the contract above it stays checkable.
//!
//! The split also means there is one place where SQLite's behaviour is compared against the contract:
//! [`SynraDb::migrate`] applies [`crate::db::MIGRATIONS`] through `rusqlite` and records the version the way
//! [`crate::db::apply`] says to. A second implementation of the ordering would be a second set of rules.
//!
//! # Why `bundled`
//!
//! Because a kernel that used whatever SQLite the machine happened to have would behave differently on machines with
//! different versions — and the feature that matters here, `ON DELETE CASCADE` with `foreign_keys = ON`, is a pragma the
//! operating system's copy may or may not honour. The bundle is compiled once and is the same everywhere.
//!
//! # What is deliberate about the pragmas
//!
//! [`crate::db::PRAGMAS`] is applied on every open, not only on creation. `foreign_keys` is **per connection** in SQLite
//! and defaults to off, so a connection opened without it silently accepts orphaned rows — and the failure surfaces as
//! data that cannot be joined rather than as an error. The migration module says why the checks run here rather than in
//! the caller; this is where they run.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::db::{Health, PRAGMAS, latest_version};
use crate::records::RowError;

mod audit;
mod devices;
mod identities;
mod intents;
mod migrations;
mod pairing;
mod sync;
mod sync_log;
mod plugins;
mod storage;
mod settings;

pub use migrations::migration_versions;
pub use pairing::Paired;
pub use settings::ConfigChange;

#[cfg(test)]
mod tests;

/// Why a database operation failed.
///
/// # Why the SQLite error is kept as text rather than as a variant
///
/// A public error holding `rusqlite::Error` is a promise about *that* crate's version: a minor release would change this
/// crate's error type, and a caller matching on a variant would stop compiling. The design document's rule for the stable
/// crates is that errors carry the kernel's own vocabulary and the third-party detail goes in a string, where it is
/// useful and not a promise.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DbError {
    /// The file could not be opened.
    #[error("could not open {}: {why}", path.display())]
    Open {
        /// The path.
        path: std::path::PathBuf,
        /// What SQLite said.
        why: String,
    },

    /// A statement failed.
    #[error("the database refused a statement: {why}")]
    Statement {
        /// What SQLite said.
        why: String,
    },

    /// The database's schema is newer than this build understands.
    ///
    /// # Why this is refused rather than opened
    ///
    /// A newer schema is a database written by a newer kernel. Opening it would run this build's migrations against a
    /// shape they were not written for — and the damage is a schema that is neither version, which no later build can
    /// repair because it cannot tell what it started from.
    #[error("the database is at schema {found} and this build understands up to {known}")]
    FromTheFuture {
        /// The version recorded.
        found: u32,
        /// What this build knows.
        known: u32,
    },

    /// A row could not be turned into a type.
    #[error(transparent)]
    Row(#[from] RowError),

    /// A value could not be turned into the JSON text a column holds.
    ///
    /// # Why this is a distinct variant rather than a [`DbError::Statement`]
    ///
    /// Because it is refused **before** the statement runs, and it is this crate's own doing rather than SQLite's. A
    /// caller that matched only on [`DbError::Statement`] would see a config write that failed for a reason no statement
    /// explains — which is how a missing setting becomes a support question.
    #[error("could not write a value as JSON: {why}")]
    NotJson {
        /// What `serde_json` said.
        why: String,
    },
}

/// The kernel's database.
///
/// # Why one connection rather than a pool
///
/// The kernel is one process, and its writes are ordered by the work that produces them. A pool exists to let many
/// callers proceed at once, and here that would mean two writers racing on the same rows — with SQLite's own locking as
/// the only thing between them. A single connection makes the ordering a property of the code rather than of a lock.
pub struct SynraDb {
    connection: Connection,
}

impl std::fmt::Debug for SynraDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection is not printable, and printing a database handle would leak its path into a log line.
        f.write_str("SynraDb")
    }
}

impl SynraDb {
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
        .map_err(|error| DbError::Open { path: path.to_path_buf(), why: error.to_string() })?;

        let db = Self { connection };
        db.apply_pragmas()?;
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
        let db = Self { connection };
        db.apply_pragmas()?;
        Ok(db)
    }

    /// Whether the database is usable.
    ///
    /// The `integrity_check` the design document asks for at start-up, reduced to the question a caller asks.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the check itself cannot run, which is a different answer from "the database is
    /// damaged" and must not be reported as one.
    pub fn health(&self) -> Result<Health, DbError> {
        let mut statement = self
            .connection
            .prepare("PRAGMA integrity_check")
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows: Vec<String> = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(crate::db::interpret_integrity(&rows))
    }

    /// Writes a consistent copy of the database to `destination`.
    ///
    /// # Why `VACUUM INTO` rather than copying the file
    ///
    /// Because a copy of a live database is a copy of a database mid-write: the write-ahead log is a separate file, the
    /// pages are in whatever order the last transaction left them, and what comes out is a file that may not open at all.
    /// `VACUUM INTO` is the engine's own answer — it reads a consistent snapshot and writes a compacted database — and it
    /// is a single statement, so there is nothing for this crate to get wrong in between.
    ///
    /// # Why an existing destination is refused rather than overwritten
    ///
    /// Because the caller is usually a user making a backup *before* something risky, and the tool is not in a position to
    /// know whether the file already there is the one they meant to replace. `VACUUM INTO` refuses an existing file
    /// itself; this checks first so the error can say **which** file, rather than the engine's bare complaint.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the destination exists or the vacuum cannot run.
    pub fn backup_to(&self, destination: &Path) -> Result<(), DbError> {
        if destination.exists() {
            return Err(DbError::Statement {
                why: format!(
                    "{} already exists; a backup does not overwrite one, because the file there may be the one you meant to keep",
                    destination.display()
                ),
            });
        }
        // ★ A bound parameter rather than a formatted string: the path comes from a user, and a quote in it would
        // otherwise end the SQL literal and continue as syntax. `VACUUM INTO` takes an expression, so a placeholder is
        // allowed here.
        self.connection
            .execute("VACUUM INTO ?1", [destination.to_string_lossy().as_ref()])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
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
    fn refuse_a_future_schema(&self) -> Result<(), DbError> {
        let Some(recorded) = self.recorded_version()? else {
            return Ok(());
        };
        if recorded > latest_version() {
            return Err(DbError::FromTheFuture { found: recorded, known: latest_version() });
        }
        Ok(())
    }
}

/// The wall clock, in milliseconds since the epoch.
///
/// # Why the wall clock and not a monotonic reading
///
/// Every `*_ms` column is read by a process that did not write it — a `doctor` run, a later kernel — and a monotonic
/// reading is only comparable within one process. The same reading that made the daemon's claim file work: a value
/// crossing a process boundary has to be a wall-clock one.
#[must_use]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_millis()).unwrap_or(i64::MAX))
}
