//! A version switch and its inherited consent are one database transaction.

use rusqlite::params;

use super::{DbError, SynraDb};

/// The verified version being committed and the previous consent it may inherit.
#[derive(Debug)]
pub struct PluginReplacement<'a> {
    /// Installed identifier.
    pub plugin_id: &'a str,
    /// New version.
    pub version: &'a str,
    /// Headless artifact name, empty for UI-only packages.
    pub artifact: &'a str,
    /// Artifact digest, empty for UI-only packages.
    pub digest: &'a str,
    /// Exact new manifest bytes as UTF-8.
    pub manifest: &'a str,
    /// Digest of those bytes.
    pub manifest_digest: &'a str,
    /// Previous manifest digest, only when the verified publisher and permissions permit inheriting its decisions.
    pub previous_manifest_digest: Option<&'a str>,
    /// Capabilities retained by the new manifest; removed capabilities lose their grants.
    pub capabilities: &'a [String],
    /// Who signed the new package, when it was signed.
    pub publisher_id: Option<&'a str>,
    /// The signing key's fingerprint, when there was a signature.
    pub fingerprint: Option<&'a str>,
    /// Commit time in epoch milliseconds.
    pub now_ms: i64,
}

impl SynraDb {
    /// Atomically changes the active version and either carries matching consent forward or clears approval.
    ///
    /// No permission is added or granted here. Existing granted and denied choices and their decision times survive only
    /// when every decision belongs to the supplied previous manifest. Any failure leaves all previous rows unchanged.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] for a missing installed row or a refused write; [`DbError::NotJson`] for serialization.
    pub fn replace_plugin_version(
        &self,
        replacement: &PluginReplacement<'_>,
    ) -> Result<(), DbError> {
        timed_write!(self, "plugin", {
            let capabilities =
                serde_json::to_string(replacement.capabilities).map_err(|error| {
                    DbError::NotJson {
                        why: error.to_string(),
                    }
                })?;
            let operation = || -> rusqlite::Result<()> {
                let transaction = self.connection.unchecked_transaction()?;
                let preserve: bool = transaction.query_row(
                    "SELECT ?2 IS NOT NULL AND (?3 = '[]' OR EXISTS (SELECT 1 FROM plugin_grants WHERE plugin_id = ?1))
                     AND NOT EXISTS (SELECT 1 FROM plugin_grants WHERE plugin_id = ?1 AND manifest_digest != ?2)",
                    params![replacement.plugin_id, replacement.previous_manifest_digest, capabilities], |row| row.get(0),
                )?;
                let changed = transaction.execute(
                    "UPDATE plugins SET enabled = CASE WHEN ?2 THEN enabled ELSE 0 END,
                     trusted = CASE WHEN ?3 THEN trusted ELSE 0 END, updated_at_ms = ?4 WHERE plugin_id = ?1",
                    params![replacement.plugin_id, replacement.previous_manifest_digest.is_some(), preserve, replacement.now_ms],
                )?;
                if changed == 0 {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                if preserve {
                    transaction.execute("DELETE FROM plugin_grants WHERE plugin_id = ?1 AND capability NOT IN (SELECT value FROM json_each(?2))", params![replacement.plugin_id, capabilities])?;
                    transaction.execute(
                        "UPDATE plugin_grants SET manifest_digest = ?2 WHERE plugin_id = ?1",
                        params![replacement.plugin_id, replacement.manifest_digest],
                    )?;
                } else {
                    transaction.execute(
                        "DELETE FROM plugin_grants WHERE plugin_id = ?1",
                        params![replacement.plugin_id],
                    )?;
                }
                transaction.execute(
                    "UPDATE plugin_versions SET active = 0 WHERE plugin_id = ?1 AND active = 1",
                    params![replacement.plugin_id],
                )?;
                transaction.execute(
                    "INSERT INTO plugin_versions
                     (plugin_id, version, artifact, digest, manifest, publisher_id, fingerprint, installed_ms, active)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1) ON CONFLICT(plugin_id, version) DO UPDATE SET
                     artifact = excluded.artifact, digest = excluded.digest, manifest = excluded.manifest,
                     publisher_id = excluded.publisher_id, fingerprint = excluded.fingerprint,
                     installed_ms = excluded.installed_ms, active = 1",
                    params![
                        replacement.plugin_id,
                        replacement.version,
                        replacement.artifact,
                        replacement.digest,
                        replacement.manifest,
                        replacement.publisher_id,
                        replacement.fingerprint,
                        replacement.now_ms
                    ],
                )?;
                transaction.commit()
            };
            operation().map_err(|error| DbError::Statement {
                why: error.to_string(),
            })
        })
    }
}

#[cfg(test)]
mod tests;
