//! The background update policy and schedule shared by windowed and headless hosts.

use std::time::Duration;

use synra_plugin_api::update::UpdatePolicy;
use synra_store::SynraDb;
use synra_store::{DbError, PluginUpdateCheck};

use crate::supervisor::Cancellation;

/// The setting selecting never, notify-only, auto-minor or auto-all.
pub const AUTO_UPDATE_KEY: &str = "plugins.auto_update";
/// The registry source associated with a persisted update check and automatic install.
pub const REGISTRY_KEY: &str = "plugins.registry";
/// A successful check remains current for one day, for its installed version and registry.
pub const CHECK_EVERY_MS: i64 = 24 * 60 * 60 * 1000;
/// Hosts revisit settings and due versions every five minutes; cancellation interrupts the wait.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Reads the serialized source setting so callers can reject an answer from a source the user replaced.
///
/// # Errors
///
/// [`synra_store::DbError`] when the configuration cannot be read.
pub fn registry_setting(db: &SynraDb) -> Result<Option<String>, DbError> {
    Ok(db
        .config()?
        .into_iter()
        .find(|row| row.key == REGISTRY_KEY)
        .map(|row| row.value))
}

/// Reads the user's policy under the caller's database lock. Absent or unreadable settings permit notices only.
#[must_use]
pub fn configured_policy(db: &SynraDb) -> Option<UpdatePolicy> {
    let Ok(rows) = db.config() else {
        return Some(UpdatePolicy::NotifyOnly);
    };
    match rows
        .iter()
        .find(|row| row.key == AUTO_UPDATE_KEY)
        .and_then(|row| serde_json::from_str::<String>(&row.value).ok())
        .as_deref()
    {
        Some("never") => None,
        Some("auto-minor") => Some(UpdatePolicy::AutoMinor),
        Some("auto-all") => Some(UpdatePolicy::AutoAll),
        _ => Some(UpdatePolicy::NotifyOnly),
    }
}

/// Whether this version needs a fresh registry answer.
///
/// A failed automatic install sets `retry_at_ms`; that deadline outranks the daily one. Once the retry bound is spent the
/// field is `None` again and the daily check takes over. `None` for both means never checked, and a clock that moved
/// backwards is due rather than silent.
#[must_use]
pub const fn due(last_ms: Option<i64>, retry_at_ms: Option<i64>, now_ms: i64) -> bool {
    if let Some(last) = last_ms
        && now_ms < last
    {
        return true;
    }
    if let Some(retry) = retry_at_ms {
        return now_ms >= retry;
    }
    match last_ms {
        None => true,
        Some(last) => now_ms < last || now_ms.saturating_sub(last) >= CHECK_EVERY_MS,
    }
}

/// Selects installed plugins due for a registry check, using the persisted retry schedule in both hosts.
///
/// The caller releases its database lock before performing any network or guest operation.
///
/// # Errors
///
/// [`DbError`] when installed plugins or saved checks cannot be read.
pub fn due_plugins(db: &SynraDb, now_ms: i64) -> Result<Vec<String>, DbError> {
    if configured_policy(db).is_none() {
        return Ok(Vec::new());
    }
    let checks = db.plugin_update_checks()?;
    let by_plugin: std::collections::BTreeMap<_, _> = checks
        .iter()
        .map(|check| (check.plugin_id.as_str(), check))
        .collect();
    Ok(db
        .plugins()?
        .into_iter()
        .filter_map(|row| {
            let check = by_plugin.get(row.plugin_id.as_str());
            due(
                check.map(|check| check.checked_at_ms),
                check.and_then(|check| check.retry_at_ms),
                now_ms,
            )
            .then_some(row.plugin_id)
        })
        .collect())
}

/// Persists a failed automatic attempt only while its policy, version, source and candidate are still current.
///
/// Cancellation or a changed policy returns `false`, as does a superseded check; neither should create a retry.
/// The caller holds its database lock only for this decision and write.
///
/// # Errors
///
/// [`DbError`] when the failure cannot be recorded; callers must report this rather than claim a retry was scheduled.
pub fn record_failure(
    db: &SynraDb,
    check: &PluginUpdateCheck,
    policy: UpdatePolicy,
    cancel: &Cancellation,
    now_ms: i64,
) -> Result<bool, DbError> {
    if cancel.is_cancelled()
        || policy == UpdatePolicy::NotifyOnly
        || configured_policy(db) != Some(policy)
    {
        return Ok(false);
    }
    db.note_update_failure(check, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_requires_an_explicit_automatic_choice() {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("schema");
        assert_eq!(configured_policy(&db), Some(UpdatePolicy::NotifyOnly));
        for (value, expected) in [
            (serde_json::json!("never"), None),
            (
                serde_json::json!("notify-only"),
                Some(UpdatePolicy::NotifyOnly),
            ),
            (
                serde_json::json!("auto-minor"),
                Some(UpdatePolicy::AutoMinor),
            ),
            (serde_json::json!("auto-all"), Some(UpdatePolicy::AutoAll)),
            (serde_json::json!(true), Some(UpdatePolicy::NotifyOnly)),
            (serde_json::json!("unknown"), Some(UpdatePolicy::NotifyOnly)),
        ] {
            db.set_config(AUTO_UPDATE_KEY, &value, 1).expect("setting");
            assert_eq!(configured_policy(&db), expected);
        }
    }

    #[test]
    fn daily_checks_handle_boundaries_and_clock_changes() {
        assert!(due(None, None, 0));
        assert!(!due(Some(100), None, 100 + CHECK_EVERY_MS - 1));
        assert!(due(Some(100), None, 100 + CHECK_EVERY_MS));
        assert!(due(Some(100), None, 99));
        assert!(due(Some(i64::MIN), None, i64::MAX));
    }

    #[test]
    fn retry_scheduling_honors_cancellation_and_policy_changes() {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("schema");
        let plugin = "@acme/hello";
        db.insert_plugin(plugin, false, false, "good", 1, 1)
            .expect("plugin");
        db.record_plugin_version(&synra_store::PluginVersionRecord {
            plugin_id: plugin,
            version: "1.0.0",
            artifact: "wasm",
            digest: "digest",
            manifest: "{}",
            installed_ms: 1,
            ..Default::default()
        })
        .expect("version");
        let check = PluginUpdateCheck {
            plugin_id: plugin.to_owned(),
            current_version: "1.0.0".to_owned(),
            checked_at_ms: 100,
            registry: None,
            available_version: Some("1.1.0".to_owned()),
            added_capabilities: Vec::new(),
            attempts: 0,
            retry_at_ms: None,
        };
        db.save_plugin_update_check(&check).expect("save");
        db.set_config(AUTO_UPDATE_KEY, &serde_json::json!("auto-all"), 1)
            .expect("policy");
        let cancelled = Cancellation::new();
        cancelled.cancel();
        assert!(
            !record_failure(&db, &check, UpdatePolicy::AutoAll, &cancelled, 100)
                .expect("cancelled")
        );
        let cancel = Cancellation::new();
        db.set_config(AUTO_UPDATE_KEY, &serde_json::json!("never"), 2)
            .expect("disable");
        assert!(!record_failure(&db, &check, UpdatePolicy::AutoAll, &cancel, 100).expect("off"));
        assert!(due_plugins(&db, i64::MAX).expect("disabled").is_empty());
        db.set_config(AUTO_UPDATE_KEY, &serde_json::json!("auto-minor"), 3)
            .expect("policy change");
        assert!(
            !record_failure(&db, &check, UpdatePolicy::AutoAll, &cancel, 100).expect("changed")
        );
        assert!(record_failure(&db, &check, UpdatePolicy::AutoMinor, &cancel, 100).expect("retry"));
        let saved = db
            .plugin_update_check(plugin)
            .expect("read")
            .expect("check");
        let deadline = saved.retry_at_ms.expect("deadline");
        assert!(due_plugins(&db, deadline - 1).expect("before").is_empty());
        assert_eq!(due_plugins(&db, deadline).expect("due"), vec![plugin]);
        assert_eq!(
            due_plugins(&db, 99).expect("clock moved back"),
            vec![plugin]
        );
    }

    #[test]
    fn a_retry_deadline_outranks_the_daily_check() {
        assert!(!due(Some(100), Some(1_000), 999));
        assert!(due(Some(100), Some(1_000), 1_000));
        assert!(due(Some(100), Some(1_000), 2_000));
        // A retry deadline in the past does not wait for the day.
        assert!(due(Some(100), Some(50), 60));
        assert!(due(Some(100), Some(1_000), 99));
    }
}
