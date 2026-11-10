//! Update checks survive restarts and only describe the version that was checked.

use rusqlite::OptionalExtension as _;
use rusqlite::params;

use super::{DbError, SynraDb};

/// The wait after the first failed automatic install; each further failure doubles it.
const RETRY_BASE_MS: i64 = 30 * 60 * 1000;
/// After three failed attempts the daily check takes over; no unbounded counter is needed.
const MAX_ATTEMPTS: u32 = 3;

/// The last successful registry check for one installed version, including a negative result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginUpdateCheck {
    /// Which installed plugin was checked.
    pub plugin_id: String,
    /// The version installed when the request began.
    pub current_version: String,
    /// When the registry answered, in milliseconds since the epoch.
    pub checked_at_ms: i64,
    /// The serialized `plugins.registry` setting when the request began, or `None` when absent.
    pub registry: Option<String>,
    /// The newer version, or `None` when no update was available.
    pub available_version: Option<String>,
    /// Capabilities in the published manifest absent from the installed manifest.
    pub added_capabilities: Vec<String>,
    /// Failed automatic attempts for this installed version, candidate and source, capped at three.
    pub attempts: u32,
    /// When a failed automatic install may be tried again, or `None` for "at the daily check".
    pub retry_at_ms: Option<i64>,
}

impl SynraDb {
    /// Records a successful check if that version is still installed.
    ///
    /// Returns `false` if the plugin was removed or replaced while the registry request was in flight. The test and
    /// write share one statement, so a late answer cannot resurrect an uninstalled plugin's update.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when SQLite refuses the write, or [`DbError::NotJson`] when capabilities cannot serialize.
    pub fn save_plugin_update_check(&self, check: &PluginUpdateCheck) -> Result<bool, DbError> {
        timed_write!(self, "plugin", {
            let capabilities =
                serde_json::to_string(&check.added_capabilities).map_err(|error| {
                    DbError::NotJson {
                        why: error.to_string(),
                    }
                })?;
            let written = self.connection.execute(
                "INSERT INTO plugin_update_checks
                    (plugin_id, current_version, checked_at_ms, available_version, added_capabilities, registry, attempts, retry_at_ms)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, 0, NULL
                 WHERE EXISTS (SELECT 1 FROM plugin_versions
                     WHERE plugin_id = ?1 AND version = ?2 AND active = 1)
                    AND ?6 IS (SELECT value FROM config WHERE key = 'plugins.registry')
                 ON CONFLICT (plugin_id) DO UPDATE SET
                    current_version = excluded.current_version,
                    checked_at_ms = excluded.checked_at_ms,
                    available_version = excluded.available_version,
                    registry = excluded.registry,
                    added_capabilities = excluded.added_capabilities,
                    attempts = CASE WHEN plugin_update_checks.available_version IS excluded.available_version
                                         AND plugin_update_checks.current_version = excluded.current_version
                                         AND plugin_update_checks.registry IS excluded.registry
                                    THEN plugin_update_checks.attempts ELSE 0 END,
                    retry_at_ms = CASE WHEN plugin_update_checks.available_version IS excluded.available_version
                                            AND plugin_update_checks.current_version = excluded.current_version
                                            AND plugin_update_checks.registry IS excluded.registry
                                       THEN plugin_update_checks.retry_at_ms ELSE NULL END",
                params![check.plugin_id, check.current_version, check.checked_at_ms,
                    check.available_version, capabilities, check.registry],
            ).map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(written != 0)
        })
    }

    /// Records a failed automatic install only while its checked version, candidate and registry are still current.
    ///
    /// The first failure waits half an hour, the second an hour, and the third falls back to the daily check. This is
    /// deliberately bounded: a package that is genuinely broken must not turn every five-minute poll into a download.
    /// Returns `false` for a superseded check or an absent update. Validation and increment share one SQL statement so
    /// an old attempt cannot schedule retries for a different candidate or resurrect an uninstalled plugin.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the row cannot be read or written.
    pub fn note_update_failure(
        &self,
        check: &PluginUpdateCheck,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        timed_write!(self, "plugin", {
            let recorded: Option<Option<i64>> = self
                .connection
                .query_row(
                    "UPDATE plugin_update_checks
                     SET attempts = MIN(attempts + 1, ?7),
                         retry_at_ms = CASE attempts WHEN 0 THEN ?6 WHEN 1 THEN ?8 ELSE NULL END
                     WHERE plugin_id = ?1 AND current_version = ?2
                         AND available_version = ?3 AND registry IS ?4 AND checked_at_ms = ?5
                         AND registry IS (SELECT value FROM config WHERE key = 'plugins.registry')
                         AND EXISTS (SELECT 1 FROM plugin_versions
                             WHERE plugin_id = ?1 AND version = ?2 AND active = 1)
                     RETURNING retry_at_ms",
                    params![
                        check.plugin_id,
                        check.current_version,
                        check.available_version,
                        check.registry,
                        check.checked_at_ms,
                        now_ms.saturating_add(RETRY_BASE_MS),
                        MAX_ATTEMPTS,
                        now_ms.saturating_add(RETRY_BASE_MS * 2)
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| DbError::Statement {
                    why: error.to_string(),
                })?;
            Ok(recorded.is_some())
        })
    }

    /// Successful checks for versions that are still installed, ordered by plugin identifier.
    ///
    /// Changing the active version invalidates its old result even when another host made that change.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] for an unreadable table or [`DbError::NotJson`] for corrupt capability data.
    pub fn plugin_update_checks(&self) -> Result<Vec<PluginUpdateCheck>, DbError> {
        self.read_plugin_update_checks(None)
    }

    /// The successful check of one plugin's current version, if it has been checked.
    ///
    /// # Errors
    ///
    /// As [`Self::plugin_update_checks`].
    pub fn plugin_update_check(
        &self,
        plugin_id: &str,
    ) -> Result<Option<PluginUpdateCheck>, DbError> {
        self.read_plugin_update_checks(Some(plugin_id))
            .map(|rows| rows.into_iter().next())
    }

    fn read_plugin_update_checks(
        &self,
        plugin_id: Option<&str>,
    ) -> Result<Vec<PluginUpdateCheck>, DbError> {
        let mut statement = self.connection.prepare(
            "SELECT c.plugin_id, c.current_version, c.checked_at_ms, c.available_version, c.added_capabilities,
                    c.registry, c.attempts, c.retry_at_ms
             FROM plugin_update_checks c JOIN plugin_versions v
             ON v.plugin_id = c.plugin_id AND v.version = c.current_version AND v.active = 1
             WHERE (?1 IS NULL OR c.plugin_id = ?1)
                AND c.registry IS (SELECT value FROM config WHERE key = 'plugins.registry')
             ORDER BY c.plugin_id",
        ).map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map(params![plugin_id], |row| {
                Ok((
                    PluginUpdateCheck {
                        plugin_id: row.get(0)?,
                        current_version: row.get(1)?,
                        checked_at_ms: row.get(2)?,
                        registry: row.get(5)?,
                        available_version: row.get(3)?,
                        added_capabilities: Vec::new(),
                        attempts: row.get(6)?,
                        retry_at_ms: row.get(7)?,
                    },
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| DbError::Statement {
                why: error.to_string(),
            })?;
        rows.map(|row| {
            let (mut check, capabilities) = row.map_err(|error| DbError::Statement {
                why: error.to_string(),
            })?;
            check.added_capabilities =
                serde_json::from_str(&capabilities).map_err(|error| DbError::NotJson {
                    why: error.to_string(),
                })?;
            Ok(check)
        })
        .collect()
    }
}

#[cfg(test)]
mod tests;
