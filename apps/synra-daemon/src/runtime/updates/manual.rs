//! User-requested checks and replacements, independent of the background policy and daily schedule.

use synra_control::Refusal;
use synra_protocol::{PluginId, error::ErrorCode};

use super::super::Runtime;
use super::{apply, source::Sources};

pub(in super::super) fn check(
    runtime: &Runtime,
    target: Option<&str>,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    Sources::parse(&configured(runtime)?).map_err(invalid)?;
    let rows = runtime.db().plugins().map_err(internal)?;
    if let Some(plugin) = target {
        installed(runtime, plugin)?;
    }
    let cancel = synra_core::supervisor::Cancellation::new();
    let mut failures = Vec::new();
    for row in rows
        .iter()
        .filter(|row| target.is_none_or(|id| id == row.plugin_id))
    {
        if let Err(error) = super::check_one(runtime, &row.plugin_id, now_ms, &cancel, false) {
            failures.push(serde_json::json!({"pluginId":row.plugin_id,"message":error}));
        }
    }
    let checks = runtime.db().plugin_update_checks().map_err(internal)?;
    let updates: Vec<_> = checks.iter().filter(|row| target.is_none_or(|id| id == row.plugin_id))
        .map(|row| serde_json::json!({"pluginId":row.plugin_id,"currentVersion":row.current_version,
            "availableVersion":row.available_version,"addedCapabilities":row.added_capabilities,"checkedAtMs":row.checked_at_ms})).collect();
    Ok(serde_json::json!({"updateChecks":updates,"failures":failures}))
}

pub(in super::super) fn update(
    runtime: &Runtime,
    plugin: &str,
    requested: Option<&str>,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    installed(runtime, plugin)?;
    if runtime.plugin_loads.lock().safe_mode.is_some() {
        return Err(invalid("plugin updates are disabled in safe mode"));
    }
    let raw = configured(runtime)?;
    let sources = Sources::parse(&raw).map_err(invalid)?;
    let cancel = synra_core::supervisor::Cancellation::new();
    let document = sources
        .read(plugin, &cancel)
        .map_err(|error| Refusal::new(ErrorCode::DeviceOffline, error))?;
    let chosen = document.document.select(requested).map_err(invalid)?;
    if let Some(reason) = runtime.revocations.revokes(plugin, &chosen.version) {
        return Err(invalid(reason));
    }
    let package = sources.download(
        &document,
        chosen,
        &runtime.paths.cache_dir().join("registry"),
        now_ms,
        &cancel,
    )?;
    let outcome = apply::manual(
        runtime,
        (plugin, &chosen.version),
        package.path(),
        Some(&raw),
        now_ms,
    );
    package.cleanup();
    let installed = outcome.map_err(invalid)?;
    let enabled = runtime
        .db()
        .plugins()
        .map_err(internal)?
        .iter()
        .any(|row| row.plugin_id == plugin && row.should_run());
    let summary = runtime.plugin_loads.lock();
    let refused = summary
        .refused
        .iter()
        .find(|entry| entry.plugin_id.as_str() == plugin)
        .map(|entry| entry.reason.clone());
    let loaded = summary.loaded.iter().any(|id| id.as_str() == plugin);
    drop(summary);
    Ok(
        serde_json::json!({"pluginId":plugin,"version":installed.version,"updated":true,
        "enabled":enabled,"loaded":loaded,"activationError":refused,"warnings":installed.warnings}),
    )
}

fn configured(runtime: &Runtime) -> Result<String, Refusal> {
    super::registry_setting(&runtime.db())
        .map_err(internal)?
        .ok_or_else(|| {
            Refusal::new(
                ErrorCode::Unsupported,
                "configure a registry with synra plugin registry URL first",
            )
        })
}

fn installed(runtime: &Runtime, plugin: &str) -> Result<(), Refusal> {
    PluginId::parse(plugin).map_err(invalid)?;
    if runtime
        .db()
        .active_plugin(plugin)
        .map_err(internal)?
        .is_none()
    {
        return Err(Refusal::new(
            ErrorCode::PluginNotInstalled,
            format!("{plugin} is not installed"),
        ));
    }
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> Refusal {
    Refusal::new(ErrorCode::InvalidArgument, error.to_string())
}

fn internal(error: impl std::fmt::Display) -> Refusal {
    Refusal::new(ErrorCode::Internal, error.to_string())
}
