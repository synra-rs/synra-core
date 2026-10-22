//! A lifecycle switch using the kernel's retained, verified replacement bytes.

use synra_core::dispatch::PluginSet;
use synra_core::plugin_updates::configured_policy;
use synra_core::supervisor::Cancellation;
use synra_plugin_api::update::UpdatePolicy;
use synra_protocol::PluginId;

use super::super::Runtime;

pub(super) fn directory(
    runtime: &Runtime,
    target: (&str, &str),
    path: &std::path::Path,
    registry: Option<&str>,
    policy: UpdatePolicy,
    now_ms: i64,
    cancel: &Cancellation,
) -> Result<(), String> {
    let (plugin, version) = target;
    let id = PluginId::parse(plugin).map_err(|error| error.to_string())?;
    let mut set = runtime.plugins.lock();
    let prepared = {
        let db = runtime.db();
        ensure(&db, registry, policy, cancel)?;
        synra_core::install::prepare_automatic_update(
            &db,
            set.backend(),
            &runtime.plugins_dir,
            path,
            now_ms,
            synra_plugin_host::verify::HostFacts::headless(),
            policy,
        )
        .map_err(|error| format!("{}: {}", error.stage, error.reason))?
    };
    if prepared.plugin_id() != plugin || prepared.version() != version {
        return Err(
            "the verified package does not match the checked plugin and version".to_owned(),
        );
    }
    if let Some(reason) = runtime.revocations.revokes(plugin, version) {
        return Err(reason.to_string());
    }
    ensure(&runtime.db(), registry, policy, cancel)?;
    let activation = synra_core::plugin::activation_config(set.host().as_ref());
    // The set lock serializes updates and removals; the store is released while third-party migration code runs.
    let old = set.version(&id).map(str::to_owned);
    if let Some(old) = old {
        let timestamp = u64::try_from(now_ms).unwrap_or(0);
        synra_core::plugin::migrate(&mut set, &id, &old, version, timestamp)?;
        synra_core::plugin::deactivate(&mut set, &id, timestamp);
        runtime.plugin_loads.lock().record_unloaded(&id);
    }
    let outcome = {
        let mut db = runtime.db();
        ensure(&db, registry, policy, cancel).and_then(|()| {
            prepared
                .install(&mut db, now_ms)
                .map_err(|error| format!("{}: {}", error.stage, error.reason))
        })
    };
    let reloaded = reload(runtime, &mut set, &id, &activation);
    drop(set);
    outcome?;
    if let Err(error) = reloaded {
        tracing::warn!(plugin, version, %error, "replacement installed but could not activate");
    }
    tracing::info!(plugin, version, "plugin updated automatically");
    Ok(())
}

fn ensure(
    db: &synra_store::SynraDb,
    registry: Option<&str>,
    policy: UpdatePolicy,
    cancel: &Cancellation,
) -> Result<(), String> {
    if cancel.is_cancelled()
        || configured_policy(db) != Some(policy)
        || super::registry_setting(db)?.as_deref() != registry
    {
        return Err("the automatic update was cancelled or its configuration changed".to_owned());
    }
    Ok(())
}

fn reload(
    runtime: &Runtime,
    set: &mut PluginSet,
    id: &PluginId,
    activation: &str,
) -> Result<(), String> {
    let loaded = {
        let db = runtime.db();
        let enabled = db
            .plugins()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|row| row.plugin_id == id.as_str() && row.should_run());
        if !enabled {
            drop(db);
            return Ok(());
        }
        let result = synra_core::plugin::load_plugin_with_config(
            set,
            &db,
            &runtime.plugins_dir,
            id.as_str(),
            &runtime.revocations,
            activation,
        );
        drop(db);
        result
    };
    match loaded {
        Ok(id) => runtime.plugin_loads.lock().record_loaded(id),
        Err(error) => {
            runtime
                .plugin_loads
                .lock()
                .record_refused(id.as_str(), error.clone());
            return Err(error);
        }
    }
    Ok(())
}
