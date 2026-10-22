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

/// The verified version a host is committing.
///
/// # Why a record rather than eight arguments
///
/// Because the signer made the list long enough that a positional call was easy to get wrong — a plugin id where a
/// publisher belongs is the kind of swap no type catches. Named fields cost one struct and make the call sites read as
/// what they are.
#[derive(Debug, Clone)]
pub struct PluginVersionRecord<'a> {
    /// Installed identifier.
    pub plugin_id: &'a str,
    /// Version string.
    pub version: &'a str,
    /// Headless artifact name, empty for a UI-only package.
    pub artifact: &'a str,
    /// Artifact digest, empty for a UI-only package.
    pub digest: &'a str,
    /// Exact manifest bytes as UTF-8.
    pub manifest: &'a str,
    /// Who signed it, when the package was signed.
    pub publisher_id: Option<&'a str>,
    /// The signing key's fingerprint, when signed.
    pub fingerprint: Option<&'a str>,
    /// Install time in epoch milliseconds.
    pub installed_ms: i64,
}

impl Default for PluginVersionRecord<'_> {
    fn default() -> Self {
        Self {
            plugin_id: "",
            version: "",
            artifact: "",
            digest: "",
            manifest: "{}",
            publisher_id: None,
            fingerprint: None,
            installed_ms: 0,
        }
    }
}

impl SynraDb {
    /// Records the version that is now active and deactivates whatever was active before.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when either write is refused. The transaction is dropped unfinished, so nothing changed — in
    /// particular the plugin keeps whatever version it had.
    pub fn record_plugin_version(
        &self,
        record: &PluginVersionRecord<'_>,
    ) -> Result<(), DbError> {
        let plugin_id = record.plugin_id;
        timed_write!(self, "plugin", {
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
                    "INSERT INTO plugin_versions \
                         (plugin_id, version, artifact, digest, manifest, publisher_id, fingerprint, installed_ms, active) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1) \
                     ON CONFLICT(plugin_id, version) DO UPDATE SET \
                         artifact = excluded.artifact, \
                         digest = excluded.digest, \
                         manifest = excluded.manifest, \
                         publisher_id = excluded.publisher_id, \
                         fingerprint = excluded.fingerprint, \
                         installed_ms = excluded.installed_ms, \
                         active = 1",
                    params![
                        record.plugin_id,
                        record.version,
                        record.artifact,
                        record.digest,
                        record.manifest,
                        record.publisher_id,
                        record.fingerprint,
                        record.installed_ms
                    ],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            transaction
                .commit()
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
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
            .prepare(
                "SELECT version, artifact, digest, publisher_id, fingerprint \
                 FROM plugin_versions WHERE plugin_id = ?1 AND active = 1",
            )
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
        let publisher_id: Option<String> =
            row.get(3).map_err(|error| DbError::Statement { why: error.to_string() })?;
        let fingerprint: Option<String> =
            row.get(4).map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(Some(crate::records::ActiveVersion { version, artifact, digest, publisher_id, fingerprint }))
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
