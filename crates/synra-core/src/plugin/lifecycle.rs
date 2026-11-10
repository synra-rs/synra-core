use synra_plugin_host::{CallBudget, CallOutcome, Host, Work};
use synra_protocol::ids::PluginId;

use crate::dispatch::PluginSet;

pub(in crate::plugin) fn activate(
    set: &mut PluginSet,
    id: &PluginId,
    quota: &synra_plugin_host::quota::Quota,
    now_ms: u64,
    config_json: &str,
) -> Result<(), String> {
    let work = Work::Activate {
        config_json: config_json.to_owned(),
    };
    match set.call(id, &work, CallBudget::from_quota(quota), now_ms) {
        Ok(CallOutcome::Ok(_)) => Ok(()),
        Ok(CallOutcome::Failed { message, .. }) => Err(format!("its activate refused: {message}")),
        Ok(other) => Err(format!("its activate {}", other.as_str())),
        Err(error) => Err(error.to_string()),
    }
}

/// Calls one plugin's `activate` again on a set that still holds it.
pub fn reactivate_loaded(
    set: &mut PluginSet,
    id: &PluginId,
    activation: &str,
    now_ms: u64,
) -> Result<(), String> {
    let quota = set
        .quota(id)
        .ok_or_else(|| "it is not loaded, so there is nothing to re-activate".to_owned())?;
    activate(set, id, &quota, now_ms, activation)?;
    set.mark_active(id).map_err(|error| error.to_string())
}

/// The JSON a plugin receives in `activate`.
#[must_use]
pub fn activation_config(host: &dyn Host) -> String {
    serde_json::json!({
        "locale": host.locale(),
        "darkMode": host.dark_mode(),
    })
    .to_string()
}

/// Asks one plugin to bring its own data forward, before the new version is written.
pub fn migrate(
    set: &mut PluginSet,
    id: &PluginId,
    from_version: &str,
    to_version: &str,
    now_ms: u64,
) -> Result<(), String> {
    let work = Work::Migrate {
        from_version: from_version.to_owned(),
        to_version: to_version.to_owned(),
    };
    match set.call(
        id,
        &work,
        CallBudget::from_quota(&synra_plugin_host::quota::Quota::default()),
        now_ms,
    ) {
        Ok(CallOutcome::Ok(_)) => Ok(()),
        Ok(CallOutcome::Failed { message, .. }) => Err(format!("its migrate refused: {message}")),
        Ok(other) => Err(format!("its migrate {}", other.as_str())),
        Err(error) => Err(error.to_string()),
    }
}

/// Deactivates and unloads one plugin.
pub fn deactivate(set: &mut PluginSet, id: &PluginId, now_ms: u64) {
    let work = Work::Deactivate;
    let _ = set.call(
        id,
        &work,
        CallBudget::from_quota(&synra_plugin_host::quota::Quota::default()),
        now_ms,
    );
    set.unload(id);
}
