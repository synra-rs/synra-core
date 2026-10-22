//! Update checks survive restarts and only describe the version that was checked.

use rusqlite::params;

use super::{DbError, SynraDb};

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
                    (plugin_id, current_version, checked_at_ms, available_version, added_capabilities, registry)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6
                 WHERE EXISTS (SELECT 1 FROM plugin_versions
                     WHERE plugin_id = ?1 AND version = ?2 AND active = 1)
                    AND ?6 IS (SELECT value FROM config WHERE key = 'plugins.registry')
                 ON CONFLICT (plugin_id) DO UPDATE SET
                    current_version = excluded.current_version,
                    checked_at_ms = excluded.checked_at_ms,
                    available_version = excluded.available_version,
                    registry = excluded.registry,
                    added_capabilities = excluded.added_capabilities",
                params![check.plugin_id, check.current_version, check.checked_at_ms,
                    check.available_version, capabilities, check.registry],
            ).map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(written != 0)
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
            "SELECT c.plugin_id, c.current_version, c.checked_at_ms, c.available_version, c.added_capabilities, c.registry
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
    use super::*;

    fn check() -> PluginUpdateCheck {
        PluginUpdateCheck {
            plugin_id: "@acme/hello".to_owned(),
            current_version: "1.0.0".to_owned(),
            checked_at_ms: 123,
            registry: None,
            available_version: Some("2.0.0".to_owned()),
            added_capabilities: vec!["log:*".to_owned()],
        }
    }

    fn database() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("schema");
        db.insert_plugin("@acme/hello", false, false, "good", 1, 1)
            .expect("plugin");
        db.record_plugin_version("@acme/hello", "1.0.0", "wasm", "digest", "{}", 1)
            .expect("version");
        db
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
        db.record_plugin_version("@acme/hello", "2.0.0", "wasm", "new digest", "{}", 2)
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
