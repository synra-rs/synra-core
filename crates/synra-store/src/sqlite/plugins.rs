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

    /// Records what the user decided about each capability a plugin declares.
    ///
    /// # ★ Why this is the missing writer, and why it lives here
    ///
    /// `plugin_grants` had a reader (`plugin_grants`, above) and a row type and a schema and an index — and **no writer
    /// at all**. Every `INSERT INTO plugin_grants` in the workspace was in a test. So the settings screen showed two
    /// empty lists, and the loader took the manifest's own declaration as the grant instead, because there was nothing
    /// else to take.
    ///
    /// `decided_ms` and `manifest_digest` are per decision rather than per plugin because both answer "which document
    /// did the user agree to": a plugin that ships an update adding a capability has a different digest, so the rows
    /// that predate it are visibly older than the manifest now on disk. That is what makes silent capability growth
    /// detectable rather than invisible.
    ///
    /// Each row is upserted, so a user who changes their mind overwrites the decision rather than accumulating history —
    /// the audit trail is where "what happened" lives, and this table is the current state.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when a write is refused. A capability string that is not valid is *stored as given*
    /// rather than validated here: this crate does not own the capability grammar, and a refusal from the wrong layer
    /// is one the caller cannot act on.
    pub fn record_grants(
        &self,
        plugin_id: &str,
        decisions: &[(String, bool)],
        decided_ms: i64,
        manifest_digest: &str,
    ) -> Result<usize, DbError> {
        let mut statement = self
            .connection
            .prepare(
                "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(plugin_id, capability) DO UPDATE SET \
                    granted = excluded.granted, \
                    decided_ms = excluded.decided_ms, \
                    manifest_digest = excluded.manifest_digest",
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        let mut written = 0usize;
        for (capability, granted) in decisions {
            statement
                .execute(params![plugin_id, capability, i64::from(*granted), decided_ms, manifest_digest])
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            written += 1;
        }
        Ok(written)
    }

    /// Removes a plugin's record: its row and every consent decision recorded against it.
    ///
    /// # Why `&mut self`
    ///
    /// Because the two deletes have to land **together**. A window in which the row is gone and the grants remain is a
    /// plugin the interface no longer lists but whose permissions still authorise calls; the opposite window leaves a
    /// plugin with no permissions that the list still offers. Neither is a state a user could see and repair, and a
    /// transaction is what rules both out.
    ///
    /// # Returns
    ///
    /// Whether a row was removed, so a caller can tell "removed" from "there was nothing there" — a second removal is
    /// answered honestly rather than reported as a success.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when either delete is refused. The transaction is dropped unfinished, so nothing changed.
    pub fn remove_plugin(&mut self, plugin_id: &str) -> Result<bool, DbError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let removed = transaction
            .execute("DELETE FROM plugins WHERE plugin_id = ?1", params![plugin_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        // ★ The decisions go with it. A grant recorded against a plugin that no longer exists is not history worth
        // keeping — `plugin_grants` is the current state, not a log — and leaving the rows would mean a reinstall
        // inherited the old consent, which is the one thing consent must never do.
        transaction
            .execute("DELETE FROM plugin_grants WHERE plugin_id = ?1", params![plugin_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        transaction
            .commit()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(removed > 0)
    }
}
