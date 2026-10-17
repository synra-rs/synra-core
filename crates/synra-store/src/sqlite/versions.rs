//! Which version of a plugin is the one that counts.
//!
//! # Why this was missing
//!
//! Because until a caller needed to compare two devices' plugins, nothing read the table: the installer wrote it, and the host read
//! the artifact it had already loaded. The plan is the first thing that has to ask "which version is this device running", and the
//! answer is the row the partial index `plugin_versions_active` points at.

use super::{DbError, SynraDb};

impl SynraDb {
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
        let mut statement = self
            .connection
            .prepare("SELECT version, digest FROM plugin_versions WHERE plugin_id = ?1 AND active = 1")
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let mut rows = statement
            .query([plugin_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let row = rows.next().map_err(|error| DbError::Statement { why: error.to_string() })?;

        let Some(row) = row else {
            return Ok(None);
        };
        let version: String = row.get(0).map_err(|error| DbError::Statement { why: error.to_string() })?;
        let digest: String = row.get(1).map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(Some((version, digest)))
    }
}

#[cfg(test)]
mod tests;
