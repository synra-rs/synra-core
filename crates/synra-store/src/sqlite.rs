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

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::db::{Health, MIGRATIONS, PRAGMAS, VERSION_TABLE_NAME, latest_version};
use crate::records::{ConfigRow, DeviceRow, IdentityRow, PluginRow, RowError, SeenDeviceRow};

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

    /// Runs the migrations that have not been applied, and reports how many ran.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when a statement fails, naming the migration it was in — and the version table is left at
    /// the last migration that **completed**, so a retry resumes rather than starting over.
    pub fn migrate(&mut self) -> Result<u32, DbError> {
        // ★ The version table first, and it is created *outside* the per-migration transactions: it is what records that
        // a migration ran, so it has to exist before the first one is recorded. The statement is
        // `CREATE TABLE IF NOT EXISTS`, which is what makes a resumed migration safe — the second start runs it again
        // against a table that is already there.
        self.connection
            .execute_batch(crate::db::VERSION_TABLE)
            .map_err(|error| DbError::Statement {
                why: format!("creating the version table: {error}"),
            })?;

        let recorded = self.recorded_version()?;
        let pending = crate::db::schema_state(recorded).pending();
        let mut applied = 0u32;

        for migration in pending {
            // ★ Each migration is its own transaction, so a statement that fails leaves the database at the previous
            // migration rather than half-way through this one. A partially applied migration is a schema no code was
            // written for, and the next start could not tell what it began from.
            let transaction = self
                .connection
                .transaction()
                .map_err(|error| DbError::Statement { why: error.to_string() })?;

            for (index, statement) in migration.statements.iter().enumerate() {
                transaction.execute_batch(statement).map_err(|error| DbError::Statement {
                    why: format!(
                        "migration {} ({}) statement {}: {error}",
                        migration.version,
                        migration.name,
                        index + 1
                    ),
                })?;
            }

            // The version table has two columns, `id` and `version` — the shape `rusqlite_migration` uses, which the
            // migration module keeps so the two can be swapped without a data migration. So there is nowhere to record
            // *when* a migration ran, and `now_ms` is not written here: an INSERT naming a column the table does not
            // have is a syntax-level failure at the first migration of the first start.
            transaction
                .execute(
                    &format!("INSERT INTO {VERSION_TABLE_NAME} (version) VALUES (?1)"),
                    params![migration.version],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;

            transaction.commit().map_err(|error| DbError::Statement { why: error.to_string() })?;
            applied += 1;
        }

        Ok(applied)
    }

    /// The schema version this build would report.
    #[must_use]
    pub fn known_version() -> u32 {
        latest_version()
    }

    /// The schema version recorded in the file.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the version table cannot be read.
    pub fn recorded_version(&self) -> Result<Option<u32>, DbError> {
        // The table may not exist yet — a fresh file — and that is `None` rather than an error, which is what the
        // migration module's `schema_state` expects for a first start.
        let exists: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![VERSION_TABLE_NAME],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        if exists.is_none() {
            return Ok(None);
        }

        self.connection
            .query_row(&format!("SELECT MAX(version) FROM {VERSION_TABLE_NAME}"), [], |row| {
                row.get::<_, Option<u32>>(0)
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }

    /// Every paired device, ordered by name so two runs agree.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`], or [`DbError::Row`] for a row the schema should not have allowed.
    pub fn paired_devices(&self) -> Result<Vec<DeviceRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM paired_devices ORDER BY display_name, device_id",
            crate::records::columns::DEVICE.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(DeviceRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<String>>(3)?.as_deref(),
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<DeviceRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<DeviceRow>, RowError>>().map_err(DbError::from)
    }

    /// Every device the kernel has merely heard from.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn seen_devices(&self) -> Result<Vec<SeenDeviceRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM devices_seen ORDER BY last_seen_ms DESC, device_id",
            crate::records::columns::SEEN_DEVICE.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(SeenDeviceRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?.as_deref(),
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<SeenDeviceRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<SeenDeviceRow>, RowError>>().map_err(DbError::from)
    }

    /// This device's identity, if it has one.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn identity(&self) -> Result<Option<IdentityRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM identity WHERE id = 1",
            crate::records::columns::IDENTITY.join(", ")
        );
        // The four values are bound before the call, because `as_deref()` on a temporary would borrow a `String` that is
        // dropped at the end of the expression — and `from_columns` needs the borrows to outlive it.
        let row = self
            .connection
            .query_row(&sql, [], |row| {
                let device_id: Option<String> = row.get(0)?;
                let display_name: Option<String> = row.get(1)?;
                let platform: Option<String> = row.get(2)?;
                let created_at_ms: Option<i64> = row.get(3)?;
                Ok(IdentityRow::from_columns(
                    device_id.as_deref(),
                    display_name.as_deref(),
                    platform.as_deref(),
                    created_at_ms,
                ))
            })
            .optional()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        match row {
            Some(Ok(identity)) => Ok(Some(identity)),
            Some(Err(error)) => Err(DbError::Row(error)),
            None => Ok(None),
        }
    }

    /// Every plugin the kernel knows about, ordered by identifier.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn plugins(&self) -> Result<Vec<PluginRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM plugins ORDER BY plugin_id",
            crate::records::columns::PLUGIN.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(PluginRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?.as_deref(),
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<PluginRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<PluginRow>, RowError>>().map_err(DbError::from)
    }

    /// Every setting, ordered by key.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn config(&self) -> Result<Vec<ConfigRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM config ORDER BY key",
            crate::records::columns::CONFIG.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(ConfigRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<ConfigRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<ConfigRow>, RowError>>().map_err(DbError::from)
    }

    /// How many rows each table holds.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when a count cannot be read. A table the migration has not created yet is reported as
    /// absent rather than as an error, because `synra db dump` on a fresh file is a legitimate thing to run.
    pub fn counts(&self) -> Result<Vec<(String, Option<i64>)>, DbError> {
        let mut out = Vec::new();
        for table in crate::db::TABLES {
            let exists: Option<i64> = self
                .connection
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            if exists.is_none() {
                out.push(((*table).to_owned(), None));
                continue;
            }
            let count: i64 = self
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| row.get(0))
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            out.push(((*table).to_owned(), Some(count)));
        }
        Ok(out)
    }

    /// Writes this device's identity, creating it or replacing it.
    ///
    /// # Why an upsert rather than an insert
    ///
    /// The schema declares `id INTEGER PRIMARY KEY CHECK (id = 1)`, which is what makes "this device's identity" a single
    /// answer — and an `INSERT` on the second call would be a second row, which the check refuses. So the row is at a
    /// fixed id and the write replaces it.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn write_identity(&self, identity: &IdentityRow) -> Result<(), DbError> {
        self.connection
            .execute(
                "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
                 VALUES (1, ?1, ?2, ?3, ?4) \
                 ON CONFLICT(id) DO UPDATE SET \
                     device_id = excluded.device_id, \
                     display_name = excluded.display_name, \
                     platform = excluded.platform",
                params![
                    identity.device_id,
                    identity.display_name,
                    identity.platform,
                    identity.created_at_ms
                ],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Inserts a plugin row.
    ///
    /// # Why this is a real method rather than a test helper
    ///
    /// Because it is what the kernel does when a plugin is installed, and the daemon's own tests need it to build the
    /// state they assert about. A `#[cfg(test)]` helper would be invisible across the crate boundary, and the
    /// alternative — every test writing its own `INSERT` — is the schema spelled a second time in each of them, which
    /// drifts at the first column added.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the insert is refused, which for a well-formed argument means the table is absent or
    /// the identifier is already there.
    pub fn insert_plugin(
        &self,
        plugin_id: &str,
        enabled: bool,
        trusted: bool,
        health: &str,
        installed_at_ms: i64,
        updated_at_ms: i64,
    ) -> Result<(), DbError> {
        self.connection
            .execute(
                "INSERT INTO plugins (plugin_id, enabled, trusted, health, installed_at_ms, updated_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    plugin_id,
                    i64::from(enabled),
                    i64::from(trusted),
                    health,
                    installed_at_ms,
                    updated_at_ms
                ],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Whether a table exists.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the catalogue cannot be read.
    pub fn has_table(&self, name: &str) -> Result<bool, DbError> {
        let exists: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(exists.is_some())
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

/// The migrations this build knows, for a caller that wants to report them.
#[must_use]
pub fn migration_versions() -> Vec<u32> {
    MIGRATIONS.iter().map(|migration| migration.version).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database with every migration applied.
    fn migrated() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        db
    }

    // ── Opening and migrating ─────────────────────────────────────────────────────────────────────

    #[test]
    fn a_fresh_database_migrates_to_the_latest_version() {
        let mut db = SynraDb::open_in_memory().expect("opens");
        assert_eq!(db.recorded_version().expect("reads"), None, "a fresh file has no version");

        let applied = db.migrate().expect("migrates");
        assert!(applied > 0);
        assert_eq!(
            db.recorded_version().expect("reads"),
            Some(SynraDb::known_version())
        );
    }

    #[test]
    fn migrating_twice_applies_nothing_the_second_time() {
        // ★ A kernel that restarted would re-run every migration without this, and an idempotent-looking `CREATE TABLE`
        // is not idempotent: the second run fails with "table already exists", and the kernel would refuse to start on
        // any data directory it had already used.
        let mut db = migrated();
        assert_eq!(db.migrate().expect("migrates"), 0);
    }

    #[test]
    fn every_table_the_migrations_declare_exists_afterwards() {
        // The property the rest of the module relies on: a query against a table named in `TABLES` has something to
        // query.
        let db = migrated();
        for table in crate::db::TABLES {
            assert!(db.has_table(table).expect("reads"), "{table} is missing");
        }
    }

    #[test]
    fn the_migrations_create_the_columns_the_record_lists() {
        // ★ The end-to-end version of the assertion in `records`: a `SELECT` built from a column list has to name columns
        // the migration actually created. The check there is textual; this one asks the engine.
        let db = migrated();
        for (table, expected) in [
            ("paired_devices", crate::records::columns::DEVICE),
            ("devices_seen", crate::records::columns::SEEN_DEVICE),
            ("identity", crate::records::columns::IDENTITY),
            ("plugins", crate::records::columns::PLUGIN),
            ("config", crate::records::columns::CONFIG),
        ] {
            let statement = db
                .connection
                .prepare(&format!("SELECT * FROM {table} LIMIT 0"))
                .expect("prepares");
            let actual: Vec<String> = statement
                .column_names()
                .iter()
                .map(|name| (*name).to_owned())
                .collect();
            // The row's list may be a subset — a query need not select every column — but every name in it must exist,
            // and the order of the ones that do must be the order the list gives.
            let present: Vec<&str> = actual
                .iter()
                .map(String::as_str)
                .filter(|name| expected.contains(name))
                .collect();
            let wanted: Vec<&str> = expected
                .iter()
                .copied()
                .filter(|name| actual.iter().any(|a| a == name))
                .collect();
            assert_eq!(present, wanted, "{table}");
        }
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        // ★ A newer schema is a database written by a newer kernel. Opening it would run this build's migrations against
        // a shape they were not written for, and the damage is a schema that is neither version — which no later build
        // can repair because it cannot tell what it started from.
        let db = migrated();
        db.connection
            .execute(
                &format!("INSERT INTO {VERSION_TABLE_NAME} (version) VALUES (?1)"),
                params![SynraDb::known_version() + 5],
            )
            .expect("writes a future version");

        match db.refuse_a_future_schema() {
            Err(DbError::FromTheFuture { found, known }) => {
                assert_eq!(found, SynraDb::known_version() + 5);
                assert_eq!(known, SynraDb::known_version());
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_pragmas_are_applied_on_every_open() {
        // ★ `foreign_keys` is **per connection** in SQLite and defaults to off, so a connection opened without it
        // silently accepts orphaned rows — and the failure surfaces as data that cannot be joined rather than as an
        // error. Asserted rather than assumed, because "it is on by default" is exactly the belief that makes it wrong.
        let db = SynraDb::open_in_memory().expect("opens");
        let foreign_keys: i64 = db
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("reads");
        assert_eq!(foreign_keys, 1, "foreign keys are off");
    }

    #[test]
    fn a_healthy_database_says_so() {
        let db = migrated();
        let health = db.health().expect("checks");
        assert_eq!(health, Health::Sound);
    }

    #[test]
    fn the_foreign_key_cascade_the_schema_declares_is_enforced() {
        // ★ The pragma is only worth asserting if it does something. `plugin_versions` references `plugins` with
        // `ON DELETE CASCADE`, so removing a plugin has to take its versions — and without `foreign_keys = ON` the rows
        // would be left behind, pointing at a plugin that is gone.
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO plugins (plugin_id, enabled, trusted, health, installed_at_ms, updated_at_ms) \
                 VALUES ('@a/b', 1, 1, 'healthy', 0, 0)",
                [],
            )
            .expect("a plugin");
        db.connection
            .execute(
                "INSERT INTO plugin_versions \
                 (plugin_id, version, artifact, digest, manifest, installed_ms, active) \
                 VALUES ('@a/b', '1.0.0', 'a.wasm', 'sha256-x', '{}', 0, 1)",
                [],
            )
            .expect("a version");

        db.connection.execute("DELETE FROM plugins WHERE plugin_id = '@a/b'", []).expect("removes");

        let left: i64 = db
            .connection
            .query_row("SELECT COUNT(*) FROM plugin_versions", [], |row| row.get(0))
            .expect("counts");
        assert_eq!(left, 0, "the cascade did not fire, so foreign keys are off");
    }

    // ── Reading ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_database_has_no_devices_and_that_is_not_an_error() {
        // `synra db dump` and a fresh installation both need this to be an empty list rather than a failure.
        let db = migrated();
        assert!(db.paired_devices().expect("reads").is_empty());
        assert!(db.seen_devices().expect("reads").is_empty());
        assert!(db.plugins().expect("reads").is_empty());
        assert!(db.config().expect("reads").is_empty());
        assert!(db.identity().expect("reads").is_none());
    }

    #[test]
    fn a_paired_device_round_trips_through_the_engine() {
        // ★ The whole point of the record types: a row written by SQL and read back by the positional reader has to
        // arrive in the right fields. A swap between two `TEXT` columns would show up here as a name that is a platform.
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO paired_devices \
                 (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
                 VALUES ('dev_a', 'Laptop', 'windows', '[\"eventStream\"]', 1000, 2000, 0)",
                [],
            )
            .expect("a device");

        let devices = db.paired_devices().expect("reads");
        assert_eq!(devices.len(), 1);
        let device = &devices[0];
        assert_eq!(device.device_id, "dev_a");
        assert_eq!(device.display_name, "Laptop");
        assert_eq!(device.platform, "windows");
        assert_eq!(device.features, vec!["eventStream"]);
        assert_eq!(device.paired_at_ms, 1_000);
        assert_eq!(device.last_seen_ms, 2_000);
        assert!(!device.blocked);
    }

    #[test]
    fn a_blocked_device_reads_back_blocked() {
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO paired_devices \
                 (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
                 VALUES ('dev_a', 'N', 'P', '[]', 0, 0, 1)",
                [],
            )
            .expect("a device");

        let device = db.paired_devices().expect("reads").remove(0);
        assert!(device.blocked);
        assert!(!device.is_usable());
    }

    #[test]
    fn devices_come_back_in_a_stable_order() {
        // ★ Two runs of `synra devices` have to agree, or a diff of two reports is noise and a test of one is flaky.
        let db = migrated();
        for (id, name) in [("d2", "Zeta"), ("d1", "Alpha"), ("d3", "Alpha")] {
            db.connection
                .execute(
                    "INSERT INTO paired_devices \
                     (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
                     VALUES (?1, ?2, 'p', '[]', 0, 0, 0)",
                    params![id, name],
                )
                .expect("a device");
        }

        let order: Vec<String> = db
            .paired_devices()
            .expect("reads")
            .into_iter()
            .map(|device| device.device_id)
            .collect();
        // By name, then by id — so the two `Alpha`s are ordered by the key rather than by insertion.
        assert_eq!(order, vec!["d1", "d3", "d2"]);
    }

    #[test]
    fn a_identity_round_trips() {
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
                 VALUES (1, 'self', 'This machine', 'linux', 42)",
                [],
            )
            .expect("an identity");

        let identity = db.identity().expect("reads").expect("an identity");
        assert_eq!(identity.device_id, "self");
        assert_eq!(identity.display_name, "This machine");
        assert_eq!(identity.created_at_ms, 42);
    }

    #[test]
    fn the_schema_allows_only_one_identity_row() {
        // ★ The `CHECK (id = 1)` is what makes "this device's identity" a single answer. Without it a second write would
        // add a second row, and the reader — which asks for `id = 1` — would silently keep using the first.
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
                 VALUES (1, 'self', 'A', 'linux', 0)",
                [],
            )
            .expect("the first");
        let second = db.connection.execute(
            "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
             VALUES (2, 'other', 'B', 'linux', 0)",
            [],
        );
        assert!(second.is_err(), "the schema allowed a second identity row");
    }

    #[test]
    fn a_plugin_round_trips_and_knows_whether_to_run() {
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO plugins (plugin_id, enabled, trusted, health, installed_at_ms, updated_at_ms) \
                 VALUES ('@acme/hello', 1, 0, 'healthy', 10, 20)",
                [],
            )
            .expect("a plugin");

        let plugin = db.plugins().expect("reads").remove(0);
        assert_eq!(plugin.plugin_id, "@acme/hello");
        assert!(plugin.enabled);
        assert!(!plugin.trusted);
        assert!(!plugin.should_run(), "an untrusted plugin should not run");
        assert_eq!(plugin.health, "healthy");
        assert_eq!(plugin.updated_at_ms, 20);
    }

    #[test]
    fn a_config_value_round_trips_as_json() {
        let db = migrated();
        db.connection
            .execute(
                "INSERT INTO config (key, value, updated_ms) VALUES ('ui.locale', '\"zh\"', 7)",
                [],
            )
            .expect("a setting");

        let entry = db.config().expect("reads").remove(0);
        assert_eq!(entry.key, "ui.locale");
        assert_eq!(entry.json().expect("json"), serde_json::json!("zh"));
    }

    #[test]
    fn a_boolean_column_the_schema_forbids_is_reported_rather_than_read_as_true() {
        // ★ The `CHECK (x IN (0, 1))` is enforced by the engine, so this row can only arrive from a corrupt file or a
        // table created outside the migrations — which is exactly the case a reader must not interpret. The assertion is
        // that the schema refuses it, so the reader never sees it.
        let db = migrated();
        let refused = db.connection.execute(
            "INSERT INTO paired_devices \
             (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
             VALUES ('d', 'n', 'p', '[]', 0, 0, 2)",
            [],
        );
        assert!(refused.is_err(), "the schema allowed blocked = 2");
    }

    #[test]
    fn the_counts_report_every_table_including_an_absent_one() {
        // A table the migration has not created is reported as absent rather than as an error, because `synra db dump`
        // on a fresh file is a legitimate thing to run.
        let empty = SynraDb::open_in_memory().expect("opens");
        let counts = empty.counts().expect("counts");
        assert_eq!(counts.len(), crate::db::TABLES.len());
        assert!(counts.iter().all(|(_, count)| count.is_none()), "a fresh file has no tables");

        let db = migrated();
        let counts = db.counts().expect("counts");
        assert!(counts.iter().all(|(_, count)| count.is_some()), "{counts:?}");
        assert!(counts.iter().all(|(_, count)| count == &Some(0)));
    }

    #[test]
    fn the_migration_versions_are_the_ones_the_contract_declares() {
        let versions = migration_versions();
        assert_eq!(versions.len(), MIGRATIONS.len());
        // Ascending and starting at one: the contract's own rule, asserted through the binding so a mismatch between
        // the two cannot be a difference in reading.
        assert_eq!(versions[0], 1);
        assert!(versions.windows(2).all(|pair| pair[0] < pair[1]), "{versions:?}");
    }

    #[test]
    fn the_database_can_be_opened_from_a_file() {
        // The in-memory tests cover the logic; this covers the file path, which is the one a user's kernel uses.
        let path = std::env::temp_dir().join(format!("synra-db-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut db = SynraDb::open(&path).expect("opens");
        db.migrate().expect("migrates");
        assert!(db.has_table("identity").expect("reads"));
        drop(db);

        // Reopening finds the schema already there, which is the ordinary second start.
        let mut again = SynraDb::open(&path).expect("reopens");
        assert_eq!(again.migrate().expect("migrates"), 0);
        assert_eq!(again.recorded_version().expect("reads"), Some(SynraDb::known_version()));
        drop(again);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            DbError::Open { path: std::path::PathBuf::from("/tmp/x"), why: "denied".to_owned() },
            DbError::Statement { why: "no such table".to_owned() },
            DbError::FromTheFuture { found: 9, known: 3 },
            DbError::Row(RowError::Missing { column: "device_id" }),
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
        // And the future-schema message names both versions, because "incompatible" alone leaves the user with nothing.
        let text = errors[2].to_string();
        assert!(text.contains('9') && text.contains('3'), "{text}");
    }
}
