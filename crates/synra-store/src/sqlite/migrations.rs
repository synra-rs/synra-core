use rusqlite::{OptionalExtension, params};

use crate::db::{MIGRATIONS, VERSION_TABLE_NAME, latest_version};

use super::{DbError, SynraDb};

impl SynraDb {
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
}

/// The migrations this build knows, for a caller that wants to report them.
#[must_use]
pub fn migration_versions() -> Vec<u32> {
    MIGRATIONS.iter().map(|migration| migration.version).collect()
}
