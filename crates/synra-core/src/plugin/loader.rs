use std::path::Path;

use synra_capability::CapabilitySet;
use synra_observe::crash::StartupVerdict;
use synra_plugin_host::InstancePolicy;
use synra_protocol::ids::PluginId;

use crate::dispatch::{PluginSet, PluginSpec};

use super::{
    lifecycle,
    model::{LoadedSummary, Refused},
    INSTANCE_LIMIT,
};

/// Loads every plugin the database says should run.
#[must_use]
pub fn load_installed(
    set: &mut PluginSet,
    db: &parking_lot::Mutex<synra_store::SynraDb>,
    plugins_dir: &Path,
    verdict: &StartupVerdict,
    revocations: &synra_plugin_api::revocation::RevocationList,
) -> LoadedSummary {
    load_installed_with_config(set, db, plugins_dir, verdict, revocations, "{}")
}

/// The same pass, with the activation config a host has already read.
#[must_use]
pub fn load_installed_with_config(
    set: &mut PluginSet,
    db: &parking_lot::Mutex<synra_store::SynraDb>,
    plugins_dir: &Path,
    verdict: &StartupVerdict,
    revocations: &synra_plugin_api::revocation::RevocationList,
    activation: &str,
) -> LoadedSummary {
    let mut summary = LoadedSummary::default();

    if !verdict.allows_plugins() {
        summary.safe_mode = Some(verdict.explain());
        return summary;
    }

    let Ok(rows) = db.lock().plugins() else {
        return summary;
    };

    for row in rows {
        if !row.should_run() {
            continue;
        }
        match load_plugin_with_config(
            set,
            db,
            plugins_dir,
            &row.plugin_id,
            revocations,
            activation,
        ) {
            Ok(id) => summary.loaded.push(id),
            Err(reason) => summary.refused.push(Refused {
                plugin_id: row.plugin_id.clone(),
                reason,
            }),
        }
    }
    summary
}

/// Loads one plugin from its directory, whether or not the database says it should run.
pub fn load_plugin(
    set: &mut PluginSet,
    db: &parking_lot::Mutex<synra_store::SynraDb>,
    plugins_dir: &Path,
    plugin_id: &str,
    revocations: &synra_plugin_api::revocation::RevocationList,
) -> Result<PluginId, String> {
    load_plugin_with_config(set, db, plugins_dir, plugin_id, revocations, "{}")
}

/// The same load, with the activation config the caller already read.
pub fn load_plugin_with_config(
    set: &mut PluginSet,
    db: &parking_lot::Mutex<synra_store::SynraDb>,
    plugins_dir: &Path,
    plugin_id: &str,
    revocations: &synra_plugin_api::revocation::RevocationList,
    activation: &str,
) -> Result<PluginId, String> {
    let id = PluginId::try_from(plugin_id.to_owned())
        .map_err(|error| format!("the id is not usable: {error}"))?;
    let directory = plugins_dir.join(synra_store::sanitise_component(plugin_id));
    let manifest_text = std::fs::read_to_string(directory.join("manifest.json"))
        .map_err(|error| format!("the manifest could not be read: {error}"))?;
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("the manifest is not readable: {error}"))?;

    if let Some(reason) = revocations.revokes(plugin_id, &manifest.version) {
        let now = synra_store::sqlite::now_ms();
        if let Err(error) = db.lock().set_plugin_enabled(plugin_id, false, now) {
            eprintln!(
                "synra: {plugin_id} is revoked and could not be disabled in the store: {error}"
            );
        }
        return Err(format!("it is revoked and has been disabled: {reason}"));
    }

    let Some(headless) = manifest.runtime.headless.as_ref() else {
        return Err("the manifest declares no headless half".to_owned());
    };
    let wasm = std::fs::read(directory.join(&headless.artifact))
        .map_err(|error| format!("the artifact could not be read: {error}"))?;
    let digest = synra_plugin_api::manifest_digest(&manifest_text);
    let decisions = db
        .lock()
        .plugin_grants(plugin_id)
        .map_err(|error| format!("the decisions could not be read: {error}"))?;
    if decisions.is_empty() && !manifest.capabilities.is_empty() {
        return Err("it has not been confirmed by the user".to_owned());
    }
    if decisions
        .iter()
        .any(|decision| decision.manifest_digest != digest)
    {
        return Err(
            "it has changed since the user confirmed it, and needs confirming again".to_owned(),
        );
    }

    let grants = granted_of(&decisions)?;
    let partially_denied = decisions.iter().any(|decision| !decision.granted);
    let policy = if headless.stateful {
        InstancePolicy::Stateful
    } else {
        InstancePolicy::Stateless
    };
    let quota = synra_plugin_host::quota::Quota::default();
    set.load_with_lifecycle(
        PluginSpec {
            id: id.clone(),
            version: manifest.version.clone(),
            wasm,
            grants,
            policy,
            limit: INSTANCE_LIMIT,
            quota: quota.clone(),
        },
        digest,
        partially_denied,
    )
    .map_err(|error| error.to_string())?;

    let config = activation.to_owned();
    let now = u64::try_from(synra_store::sqlite::now_ms()).unwrap_or(0);
    if let Err(reason) = lifecycle::activate(set, &id, &quota, now, &config) {
        set.unload(&id);
        return Err(format!("it loaded but did not activate: {reason}"));
    }
    set.mark_active(&id).map_err(|error| {
        set.unload(&id);
        error.to_string()
    })?;
    Ok(id)
}

fn granted_of(decisions: &[synra_store::PluginGrantRow]) -> Result<CapabilitySet, String> {
    let mut grants = CapabilitySet::new();
    for decision in decisions.iter().filter(|decision| decision.granted) {
        grants.insert_str(&decision.capability).map_err(|error| {
            format!(
                "a granted capability is not usable: `{}`: {error}",
                decision.capability
            )
        })?;
    }
    Ok(grants)
}
