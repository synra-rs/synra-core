use rusqlite::params;

use crate::records::{PluginRow, RowError};

use super::{DbError, SynraDb};

impl SynraDb {
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
}
