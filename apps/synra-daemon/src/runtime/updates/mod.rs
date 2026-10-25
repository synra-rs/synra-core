//! The windowless host's supervised daily checks and verified automatic replacements.

use std::sync::Arc;

use synra_core::plugin_updates::{POLL_INTERVAL, configured_policy, due_plugins, record_failure};
use synra_core::supervisor::{Cancellation, Supervisor, TaskId, TaskSpec};
use synra_plugin_api::update::UpdatePolicy;
use synra_store::PluginUpdateCheck;

use super::Runtime;

mod apply;
mod manual;
mod source;

pub(super) use manual::{check as check_manually, update as update_manually};

pub(super) fn validate_sources(raw: &str) -> Result<(), String> {
    source::Sources::parse(raw).map(|_| ())
}

/// Registers the update worker with the daemon's shutdown supervisor.
pub(crate) fn start(
    runtime: &Arc<Runtime>,
    supervisor: &Arc<Supervisor>,
) -> Result<std::thread::JoinHandle<()>, synra_core::supervisor::SupervisorError> {
    supervisor.register(TaskSpec::service("plugins.updates"))?;
    let runtime = Arc::clone(runtime);
    synra_core::supervisor::run_task(supervisor, &TaskId::new("plugins.updates"), move |cancel| {
        while !cancel.is_cancelled() {
            for check in check_all(&runtime, synra_store::sqlite::now_ms(), cancel) {
                tracing::info!(plugin = %check.plugin_id, version = ?check.available_version, "plugin update available");
            }
            if cancel.wait(POLL_INTERVAL) {
                break;
            }
        }
        Ok(())
    })
}

/// Checks due installed versions without holding database or guest locks across network requests.
pub(crate) fn check_all(
    runtime: &Runtime,
    now_ms: i64,
    cancel: &Cancellation,
) -> Vec<PluginUpdateCheck> {
    let plugins = {
        let db = runtime.db();
        match due_plugins(&db, now_ms) {
            Ok(plugins) => plugins,
            Err(error) => {
                tracing::warn!(%error, "plugin update schedule could not be read");
                return Vec::new();
            }
        }
    };
    let mut available = Vec::new();
    for plugin in plugins {
        if cancel.is_cancelled() || configured_policy(&runtime.db()).is_none() {
            break;
        }
        match check_one(runtime, &plugin, now_ms, cancel, true) {
            Ok(Some(check)) => available.push(check),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%plugin, %error, "plugin update check failed")
            }
        }
    }
    available
}

fn check_one(
    runtime: &Runtime,
    plugin: &str,
    now_ms: i64,
    cancel: &Cancellation,
    allow_automatic: bool,
) -> Result<Option<PluginUpdateCheck>, String> {
    let (active, raw) = {
        let db = runtime.db();
        let Some(active) = db
            .active_plugin(plugin)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let Some(raw) = registry_setting(&db)? else {
            return Ok(None);
        };
        drop(db);
        (active, raw)
    };
    let sources = source::Sources::parse(&raw)?;
    let document = sources.read(plugin, cancel)?;
    let latest = document
        .document
        .latest()
        .filter(|entry| synra_registry::is_newer(&entry.version, &active.version));
    let previous = std::fs::read_to_string(
        runtime
            .plugins_dir
            .join(synra_store::sanitise_component(plugin))
            .join("manifest.json"),
    )
    .ok()
    .and_then(|text| synra_plugin_api::Manifest::from_json(&text).ok());
    let added = latest
        .and_then(|entry| entry.synra.as_ref())
        .map(|manifest| {
            manifest
                .capabilities
                .iter()
                .filter(|cap| {
                    previous
                        .as_ref()
                        .is_none_or(|old| !old.capabilities.iter().any(|old| old.cap == cap.cap))
                })
                .map(|cap| cap.cap.clone())
                .collect()
        })
        .unwrap_or_default();
    let check = PluginUpdateCheck {
        plugin_id: plugin.to_owned(),
        current_version: active.version,
        registry: Some(raw),
        checked_at_ms: now_ms,
        available_version: latest.map(|entry| entry.version.clone()),
        added_capabilities: added,
        attempts: 0,
        retry_at_ms: None,
    };
    let policy = {
        let db = runtime.db();
        if cancel.is_cancelled() || (allow_automatic && configured_policy(&db).is_none()) {
            return Ok(None);
        }
        if !db
            .save_plugin_update_check(&check)
            .map_err(|error| error.to_string())?
        {
            return Err("the installed version or registry changed during the check".to_owned());
        }
        let selected = configured_policy(&db);
        drop(db);
        selected
    };
    let Some(latest) = latest else {
        return Ok(None);
    };
    let may_load = runtime.plugin_loads.lock().safe_mode.is_none();
    if let Some(policy) =
        policy.filter(|policy| allow_automatic && *policy != UpdatePolicy::NotifyOnly)
        && check.added_capabilities.is_empty()
        && !cancel.is_cancelled()
        && may_load
    {
        match automatic(runtime, &sources, &document, latest, &check, policy, cancel) {
            Ok(()) => return Ok(None),
            Err(error) => {
                let recorded = record_failure(&runtime.db(), &check, policy, cancel, now_ms)
                    .map_err(|failure| {
                        format!("{error}; retry state could not be saved: {failure}")
                    })?;
                tracing::warn!(plugin, %error, recorded, "automatic plugin update refused");
            }
        }
    }
    Ok(Some(check))
}

fn automatic(
    runtime: &Runtime,
    sources: &source::Sources,
    document: &source::Document,
    latest: &synra_registry::Version,
    check: &PluginUpdateCheck,
    policy: UpdatePolicy,
    cancel: &Cancellation,
) -> Result<(), String> {
    if let Some(reason) = runtime
        .revocations
        .revokes(&check.plugin_id, &latest.version)
    {
        return Err(reason.to_string());
    }
    let unpacked = sources
        .download(
            document,
            latest,
            &runtime.paths.cache_dir().join("registry"),
            check.checked_at_ms,
            cancel,
        )
        .map_err(|error| error.to_string())?;
    let outcome = apply::directory(
        runtime,
        (&check.plugin_id, &latest.version),
        unpacked.path(),
        check.registry.as_deref(),
        policy,
        check.checked_at_ms,
        cancel,
    );
    unpacked.cleanup();
    outcome
}

fn registry_setting(db: &synra_store::SynraDb) -> Result<Option<String>, String> {
    synra_core::plugin_updates::registry_setting(db).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
