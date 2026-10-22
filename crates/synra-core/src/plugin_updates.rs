//! The background update policy and schedule shared by windowed and headless hosts.

use std::time::Duration;

use synra_plugin_api::update::UpdatePolicy;
use synra_store::SynraDb;

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
pub fn registry_setting(db: &SynraDb) -> Result<Option<String>, synra_store::DbError> {
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

/// An unchecked version, an expired check or a clock that moved backwards requires a fresh answer.
#[must_use]
pub const fn due(last_ms: Option<i64>, now_ms: i64) -> bool {
    match last_ms {
        None => true,
        Some(last) => now_ms < last || now_ms.saturating_sub(last) >= CHECK_EVERY_MS,
    }
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
        assert!(due(None, 0));
        assert!(!due(Some(100), 100 + CHECK_EVERY_MS - 1));
        assert!(due(Some(100), 100 + CHECK_EVERY_MS));
        assert!(due(Some(100), 99));
        assert!(due(Some(i64::MIN), i64::MAX));
    }
}
