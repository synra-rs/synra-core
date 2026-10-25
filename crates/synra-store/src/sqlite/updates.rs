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
mod tests {
    use super::super::PluginVersionRecord;
    use super::*;

    fn check() -> PluginUpdateCheck {
        PluginUpdateCheck {
            plugin_id: "@acme/hello".to_owned(),
            current_version: "1.0.0".to_owned(),
            checked_at_ms: 123,
            registry: None,
            available_version: Some("2.0.0".to_owned()),
            added_capabilities: vec!["log:*".to_owned()],
            attempts: 0,
            retry_at_ms: None,
        }
    }

    fn database() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("schema");
        db.insert_plugin("@acme/hello", false, false, "good", 1, 1)
            .expect("plugin");
        db.record_plugin_version(&PluginVersionRecord {
            plugin_id: "@acme/hello",
            version: "1.0.0",
            artifact: "wasm",
            digest: "digest",
            manifest: "{}",
            installed_ms: 1,
            ..Default::default()
        })
        .expect("version");
        db
    }

    #[test]
    fn a_failed_automatic_install_is_retried_sooner_than_a_day() {
        // ★ A transient failure used to wait for tomorrow. The first two failures back off half an hour and an hour; the
        // third gives up on the fast path and leaves the daily check.
        let db = database();
        assert!(db.save_plugin_update_check(&check()).expect("save"));

        assert!(db.note_update_failure(&check(), 1_000).expect("first"));
        // The retry itself re-checks and saves; the same available version must keep the attempted count.
        assert!(db.save_plugin_update_check(&check()).expect("re-save"));
        let after_retry = db
            .plugin_update_check("@acme/hello")
            .expect("read")
            .expect("a check");
        assert_eq!(
            after_retry.attempts, 1,
            "a re-check keeps the failure count"
        );
        assert_eq!(after_retry.retry_at_ms, Some(1_000 + RETRY_BASE_MS));
        assert!(db.note_update_failure(&check(), 2_000).expect("second"));
        assert_eq!(
            db.plugin_update_check("@acme/hello")
                .expect("read")
                .expect("check")
                .retry_at_ms,
            Some(2_000 + RETRY_BASE_MS * 2)
        );
        assert!(db.note_update_failure(&check(), 3_000).expect("third"));
        let saved = db
            .plugin_update_check("@acme/hello")
            .expect("read")
            .expect("a check");
        assert_eq!(saved.attempts, MAX_ATTEMPTS);
        assert_eq!(saved.retry_at_ms, None, "the daily check takes over");
        let mut next = check();
        next.available_version = Some("3.0.0".to_owned());
        next.checked_at_ms = 4_000;
        assert!(db.save_plugin_update_check(&next).expect("new version"));
        let reset = db
            .plugin_update_check("@acme/hello")
            .expect("read")
            .expect("a check");
        assert_eq!(
            reset.attempts, 0,
            "a different version starts its own count"
        );
        assert!(
            !db.note_update_failure(&check(), 5_000)
                .expect("old candidate")
        );
    }

    #[test]
    fn a_late_failure_cannot_change_a_replacement_check() {
        let db = database();
        let first = check();
        assert!(db.save_plugin_update_check(&first).expect("save"));
        let mut replacement = first.clone();
        replacement.checked_at_ms += 1;
        assert!(
            db.save_plugin_update_check(&replacement)
                .expect("new check")
        );
        assert!(!db.note_update_failure(&first, 1_000).expect("late failure"));
        assert_eq!(
            db.plugin_update_check(&first.plugin_id).expect("read"),
            Some(replacement)
        );
        db.record_plugin_version(&PluginVersionRecord {
            plugin_id: "@acme/hello",
            version: "1.1.0",
            artifact: "wasm",
            digest: "new",
            manifest: "{}",
            installed_ms: 2,
            ..Default::default()
        })
        .expect("replace installed version");
        assert!(!db.note_update_failure(&first, 1_000).expect("old version"));
    }

    #[test]
    fn changing_the_source_resets_attempts_and_rejects_old_failures() {
        let db = database();
        let first = check();
        db.save_plugin_update_check(&first).expect("save");
        assert!(db.note_update_failure(&first, 1_000).expect("failure"));
        db.set_config(
            "plugins.registry",
            &serde_json::json!("https://new.example"),
            2,
        )
        .expect("source");
        assert!(!db.note_update_failure(&first, 2_000).expect("old source"));
        let mut next = first;
        next.registry = Some(serde_json::json!("https://new.example").to_string());
        assert!(
            db.save_plugin_update_check(&next)
                .expect("new source check")
        );
        assert_eq!(
            db.plugin_update_check(&next.plugin_id).expect("read"),
            Some(next)
        );
    }

    #[test]
    fn retry_deadlines_saturate_and_attempt_counts_remain_bounded() {
        let db = database();
        let first = check();
        db.save_plugin_update_check(&first).expect("save");
        assert!(db.note_update_failure(&first, i64::MAX).expect("failure"));
        assert_eq!(
            db.plugin_update_check(&first.plugin_id)
                .expect("read")
                .expect("check")
                .retry_at_ms,
            Some(i64::MAX)
        );
        for _ in 0..10 {
            assert!(db.note_update_failure(&first, i64::MAX).expect("failure"));
        }
        let saved = db
            .plugin_update_check(&first.plugin_id)
            .expect("read")
            .expect("check");
        assert_eq!(saved.attempts, MAX_ATTEMPTS);
        assert_eq!(saved.retry_at_ms, None);
        let mut negative = first;
        negative.available_version = None;
        db.save_plugin_update_check(&negative).expect("no update");
        assert!(
            !db.note_update_failure(&negative, 1_000)
                .expect("no automatic attempt")
        );
    }

    #[test]
    fn a_negative_check_replaces_an_update_and_keeps_its_time() {
        let db = database();
        let mut check = check();
        assert!(db.save_plugin_update_check(&check).expect("save"));
        assert_eq!(
            db.plugin_update_checks().expect("read"),
            vec![check.clone()]
        );
        check.available_version = None;
        check.added_capabilities.clear();
        check.checked_at_ms = 456;
        assert!(db.save_plugin_update_check(&check).expect("replace"));
        assert_eq!(db.plugin_update_checks().expect("read"), vec![check]);
    }

    #[test]
    fn replacing_a_version_invalidates_its_check_and_refuses_a_late_answer() {
        let db = database();
        assert!(db.save_plugin_update_check(&check()).expect("save"));
        db.record_plugin_version(&PluginVersionRecord {
            plugin_id: "@acme/hello",
            version: "2.0.0",
            artifact: "wasm",
            digest: "new digest",
            manifest: "{}",
            installed_ms: 2,
            ..Default::default()
        })
        .expect("replace");
        assert!(db.plugin_update_checks().expect("read").is_empty());
        assert!(!db.save_plugin_update_check(&check()).expect("late answer"));
    }

    #[test]
    fn uninstalling_cascades_the_check_and_refuses_a_late_answer() {
        let mut db = database();
        assert!(db.save_plugin_update_check(&check()).expect("save"));
        assert!(db.remove_plugin("@acme/hello").expect("remove"));
        assert!(db.plugin_update_checks().expect("read").is_empty());
        assert!(!db.save_plugin_update_check(&check()).expect("late answer"));
        let remaining: i64 = db
            .connection
            .query_row("SELECT COUNT(*) FROM plugin_update_checks", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(remaining, 0);
    }

    #[test]
    fn corrupt_capabilities_are_reported_instead_of_hidden() {
        let db = database();
        db.save_plugin_update_check(&check()).expect("save");
        db.connection
            .execute(
                "UPDATE plugin_update_checks SET added_capabilities = 'broken'",
                [],
            )
            .expect("corrupt");
        assert!(matches!(
            db.plugin_update_checks(),
            Err(DbError::NotJson { .. })
        ));
    }

    #[test]
    fn switching_registries_invalidates_checks_and_refuses_a_late_answer() {
        let db = database();
        let mut check = check();
        assert!(db.save_plugin_update_check(&check).expect("save"));
        let registry = serde_json::json!("https://registry.example");
        db.set_config("plugins.registry", &registry, 1)
            .expect("registry");
        assert!(db.plugin_update_checks().expect("checks").is_empty());
        assert!(!db.save_plugin_update_check(&check).expect("late answer"));
        check.registry = Some(registry.to_string());
        assert!(
            db.save_plugin_update_check(&check)
                .expect("new registry's answer")
        );
        assert_eq!(
            db.plugin_update_check(&check.plugin_id).expect("check"),
            Some(check)
        );
    }
}
