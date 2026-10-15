use rusqlite::params;

use crate::records::{PluginGrantRow, PluginRow, RowError};

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

    /// Turns a plugin on or off, and says whether it was there.
    ///
    /// # Why the caller needs to know
    ///
    /// Because "enabled a plugin that is not installed" and "enabled a plugin that was already enabled" are different
    /// situations with the same `Ok(())`. The first is a bug in the caller; the second is an ordinary double-click. The
    /// answer is a `bool` rather than a row count so the caller is not obliged to know whether SQLite reports one or
    /// zero for a no-op `UPDATE`.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn set_plugin_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        self.connection
            .execute(
                "UPDATE plugins SET enabled = ?2, updated_at_ms = ?3 WHERE plugin_id = ?1",
                params![plugin_id, i64::from(enabled), now_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        self.plugin_is_installed(plugin_id)
    }

    /// Records whether the user trusts a plugin, and says whether it was there.
    ///
    /// # Why trusting is a separate write from enabling
    ///
    /// Because the two answer different questions and the user changes them at different moments: enabling says "run
    /// this", trusting says "this is the one I installed and it has not been replaced". A single combined flag would
    /// make re-consenting — which an upgrade does whenever the manifest's capabilities change — indistinguishable from
    /// switching the plugin on, and a plugin that silently starts running is exactly what consent exists to prevent.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn set_plugin_trusted(&self, plugin_id: &str, trusted: bool, now_ms: i64) -> Result<bool, DbError> {
        self.connection
            .execute(
                "UPDATE plugins SET trusted = ?2, updated_at_ms = ?3 WHERE plugin_id = ?1",
                params![plugin_id, i64::from(trusted), now_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        self.plugin_is_installed(plugin_id)
    }

    /// Whether a plugin is installed.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the lookup is refused.
    pub fn plugin_is_installed(&self, plugin_id: &str) -> Result<bool, DbError> {
        let found: Option<i64> = self
            .connection
            .query_row("SELECT 1 FROM plugins WHERE plugin_id = ?1", params![plugin_id], |row| row.get(0))
            .ok();
        Ok(found.is_some())
    }

    /// What the user granted and refused, with the manifest the decision was made against.
    ///
    /// The digest is carried back for one reason: an upgrade whose manifest has a different digest is a request for
    /// consent again, and a caller cannot detect that from the capability list alone — a plugin that added a capability
    /// it declares but that the user had already refused looks unchanged from the list.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the lookup is refused.
    pub fn plugin_grants(&self, plugin_id: &str) -> Result<Vec<PluginGrantRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM plugin_grants WHERE plugin_id = ?1 ORDER BY capability",
            crate::records::columns::PLUGIN_GRANT.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map(params![plugin_id], |row| {
                Ok(PluginGrantRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?.as_deref(),
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<PluginGrantRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<PluginGrantRow>, RowError>>().map_err(DbError::from)
    }

    // ★ Writing grants is deliberately absent.
    //
    // It needs a delete and inserts to land together, which means a transaction, and a transaction means `&mut self` —
    // which `migrate` already takes and everything else does not. Writing it as two `&self` statements would leave a
    // window in which every capability is revoked and none granted, which is a plugin that was working and then silently
    // is not, with the cause invisible from the table. It arrives with the consent command, taking `&mut self`, rather
    // than arriving now with the guarantee quietly dropped.
}
