//! Which version of a plugin is the one that counts.
//!
//! # Why this was missing
//!
//! Because until a caller needed to compare two devices' plugins, nothing read the table, and the installer did not write it either:
//! it wrote the plugin row and the files, while this table stayed empty. The plan is the first thing that has to ask "which version
//! is this device running", and the answer is the row the partial index `plugin_versions_active` points at.
//!
//! ★ **2026-10-18: the writer came after the reader.** `active_plugin_version` was written against a table that docs claimed the
//! installer filled; it did not. `record_plugin_version` below is that missing half, and the install pipeline now calls it.

use rusqlite::params;

use super::{DbError, SynraDb};

impl SynraDb {
    /// Records an installed version as the active one.
    ///
    /// # Why this is one transaction
    ///
    /// Because "which row is active" is a fact with one answer, and two statements are needed to keep it that way: the previous
    /// active row is cleared, then this one is written. A failure between them would leave the plugin with **no** active version,
    /// which reads as "this device has nothing" to every plan that asks.
    ///
    /// The older row is kept rather than deleted: an upgrade leaves the previous artifact on disk so a rollback needs no download,
    /// and this table is what says which of the rows that directory still describes is the one in effect.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when either write is refused. The transaction is dropped unfinished, so nothing changed — in
    /// particular the plugin keeps whatever version it had.
    pub fn record_plugin_version(
        &self,
        plugin_id: &str,
        version: &str,
        artifact: &str,
        digest: &str,
        manifest: &str,
        installed_ms: i64,
    ) -> Result<(), DbError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        transaction
            .execute(
                "UPDATE plugin_versions SET active = 0 WHERE plugin_id = ?1 AND active = 1",
                params![plugin_id],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        transaction
            .execute(
                "INSERT INTO plugin_versions (plugin_id, version, artifact, digest, manifest, installed_ms, active) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1) \
                 ON CONFLICT(plugin_id, version) DO UPDATE SET \
                     artifact = excluded.artifact, \
                     digest = excluded.digest, \
                     manifest = excluded.manifest, \
                     installed_ms = excluded.installed_ms, \
                     active = 1",
                params![plugin_id, version, artifact, digest, manifest, installed_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        transaction
            .commit()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// The active version, the artifact it names and the digest of that artifact.
    ///
    /// # Why this exists next to [`SynraDb::active_plugin_version`]
    ///
    /// Because sending a package needs the file, not only the comparison. `active_plugin_version` answers "is the peer's
    /// copy the same", and it was written first; this is the same row with its third column, and the two answers come from
    /// one query so they cannot disagree about which version is in effect.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the row cannot be read, which for a migrated database means the table is absent.
    pub fn active_plugin(&self, plugin_id: &str) -> Result<Option<crate::records::ActiveVersion>, DbError> {
        let mut statement = self
            .connection
            .prepare("SELECT version, artifact, digest FROM plugin_versions WHERE plugin_id = ?1 AND active = 1")
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let mut rows = statement
            .query([plugin_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let row = rows.next().map_err(|error| DbError::Statement { why: error.to_string() })?;

        let Some(row) = row else {
            return Ok(None);
        };
        let version: String = row.get(0).map_err(|error| DbError::Statement { why: error.to_string() })?;
        let artifact: String = row.get(1).map_err(|error| DbError::Statement { why: error.to_string() })?;
        let digest: String = row.get(2).map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(Some(crate::records::ActiveVersion { version, artifact, digest }))
    }

    /// The version and artifact digest of the plugin's active row, or `None` when it has no active version.
    ///
    /// # Why `active` and not the newest
    ///
    /// Because a device can hold two versions and be running one — the installer keeps the old one so a rollback needs no download.
    /// Reporting the newest would tell a peer to skip a transfer for the version this device is **not** running, which is the one
    /// case where the plan being wrong costs a running plugin.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the row cannot be read, which for a migrated database means the table is absent.
    pub fn active_plugin_version(&self, plugin_id: &str) -> Result<Option<(String, String)>, DbError> {
        Ok(self
            .active_plugin(plugin_id)?
            .map(|active| (active.version, active.digest)))
    }
}

#[cfg(test)]
mod tests;
