//! Loading the plugins this daemon is supposed to be running.
//!
//! # Why the daemon builds the engine and the kernel does not
//!
//! Because the engine is a host's decision. `synra-core` holds [`synra_core::dispatch::PluginSet`], which is a handle
//! rather than an engine, precisely so that this windowless host and a Tauri shell can each bring one of their own. That
//! separation is only worth anything if something actually uses it, and before this module nothing did: the daemon held
//! no plugin host at all and its status report said so with a hardcoded `"loaded": false`.
//!
//! # Why one plugin's failure does not stop the rest
//!
//! Because a machine with five plugins installed and one broken must still run the other four, and a daemon that refuses
//! to start because a single artifact is missing has turned a plugin's problem into a kernel's outage. So every plugin is
//! loaded independently and each refusal is recorded with its own reason and kept in [`LoadedSummary`].
//!
//! # Why a UI-only plugin is *skipped* rather than refused
//!
//! Because a manifest with no headless half is a working plugin that happens not to run here: its interface is served by
//! the shell, not instantiated. Calling that a refusal would put a plugin author on a bug report for a plugin that works
//! exactly as declared.
//!
//! # What this does not do
//!
//! It does not activate a plugin. Loading compiles and makes a plugin *askable*; activation is a lifecycle transition with
//! its own state machine and its own refusal rules, and a loader that also activated would be a second, weaker version of
//! that state machine. What it reports is therefore "loaded", and nothing in this file claims a plugin is running.

use std::path::Path;

use synra_capability::CapabilitySet;
use synra_plugin_host::{Backend, BackendError, InstancePolicy};
use synra_protocol::ids::PluginId;

use synra_core::dispatch::{PluginSet, PluginSpec};
use synra_observe::crash::StartupVerdict;

/// How many instances one plugin may have.
///
/// # Why this is a constant here rather than in the manifest
///
/// Because the manifest's `resourceHints` are, by name, hints — soft, and ignorable. A host that took its limit from a
/// string a plugin author wrote would be taking its resource ceiling from third-party code. Four is the point where a
/// plugin stops being concurrent and starts being a memory leak with a licence.
pub(crate) const INSTANCE_LIMIT: u32 = 4;

/// Why one plugin was not loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Its identifier, as the database spells it.
    pub plugin_id: String,
    /// What stopped it.
    pub reason: String,
}

/// What a load pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedSummary {
    /// What is now askable, in the order it was loaded.
    pub loaded: Vec<PluginId>,
    /// What was not, and why.
    pub refused: Vec<Refused>,
    /// Why nothing was loaded at all, when the daemon chose not to start plugins.
    ///
    /// `Some` only in safe mode. It is a separate field rather than an entry in `refused` because the two are different
    /// statements: `refused` names plugins that failed, and this names a decision the daemon made before looking at any
    /// of them. Putting it in `refused` would attribute the refusal to a plugin that was never examined.
    pub safe_mode: Option<String>,
}

impl LoadedSummary {
    /// How many plugins this daemon can now ask.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    /// Whether a plugin with this identifier is loaded.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.loaded.contains(id)
    }
}

/// Builds the plugin set this daemon runs plugins on.
///
/// # Errors
///
/// [`BackendError`] when the engine cannot start. This is the daemon's refusal to start at all, rather than a plugin
/// being refused: a kernel that has no engine cannot run any plugin, and reporting that as "no plugins loaded" would
/// present a broken daemon as a machine with nothing installed.
///
/// # Why the engine kind is asked for rather than written down
///
/// Because a kind written here would be a decision this file makes on the engine's behalf, and the table that already
/// answers it lives in [`synra_plugin_host::BackendKind::default_for`]. A daemon is a [`synra_plugin_host::HostKind::Headless`]
/// host, so asking is both shorter and harder to get wrong than naming a variant.
pub fn build_set() -> Result<PluginSet, BackendError> {
    let kind = synra_plugin_host::BackendKind::default_for(synra_plugin_host::HostKind::Headless);
    let engine = synra_plugin_host::engine::WasmtimeBackend::new(kind)?;
    Ok(PluginSet::new(Backend::new(std::sync::Arc::new(engine))))
}

/// Loads every plugin the database says should run.
///
/// A row that is not [`synra_store::PluginRow::should_run`] is not loaded and not refused: the user switched it off or
/// never trusted it, and that is a decision already made rather than something that went wrong here.
///
/// # ★ Why the verdict is a parameter
///
/// Because safe mode has to be able to stop this, and until it was passed in, nothing could.
/// `StartupVerdict::allows_plugins` existed, was tested, and was **called only from tests** — no plugin-loading path
/// asked it. So a plugin that crashed on activation three times in a row would crash a fourth and a fifth time, and the
/// settings screen the user needs to disable it stayed unreachable. The verdict's own doc comment says that reaching
/// the settings screen is "the only outcome that has to exist"; the code that reaches it did not exist.
///
/// Taking the verdict rather than a `bool` is deliberate: a refusal can then say *which* location has been crashing,
/// which is the sentence a user needs to act on.
pub fn load_installed(
    set: &mut PluginSet,
    db: &synra_store::SynraDb,
    plugins_dir: &Path,
    verdict: &StartupVerdict,
) -> LoadedSummary {
    let mut summary = LoadedSummary::default();

    if !verdict.allows_plugins() {
        // Nothing is loaded and nothing is refused per plugin: this is not a fault in any one plugin's artifact, it is
        // the daemon choosing not to start them at all. Recorded on the summary so the status report can say so instead
        // of showing an empty list, which would read as "nothing is installed".
        summary.safe_mode = Some(verdict.explain());
        return summary;
    }

    let Ok(rows) = db.plugins() else {
        // The table being unreadable is the daemon's problem, and it is reported through its own status line; here it
        // means "nothing could be loaded" rather than "nothing is installed".
        return summary;
    };

    for row in rows {
        if !row.should_run() {
            continue;
        }
        match load_one(set, plugins_dir, &row.plugin_id) {
            Ok(id) => summary.loaded.push(id),
            Err(reason) => summary.refused.push(Refused { plugin_id: row.plugin_id.clone(), reason }),
        }
    }
    summary
}

/// Loads one plugin from its directory.
///
/// # Errors
///
/// A string saying what stopped it, because every reason here is a fact about a file on disk or a manifest a third party
/// wrote, and each one is something the user or the author needs to read rather than an error code to map elsewhere.
fn load_one(set: &mut PluginSet, plugins_dir: &Path, plugin_id: &str) -> Result<PluginId, String> {
    let id = PluginId::try_from(plugin_id.to_owned()).map_err(|error| format!("the id is not usable: {error}"))?;
    let directory = plugins_dir.join(plugin_id);
    let manifest_text = std::fs::read_to_string(directory.join("manifest.json"))
        .map_err(|error| format!("the manifest could not be read: {error}"))?;
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("the manifest is not readable: {error}"))?;

    let Some(headless) = manifest.runtime.headless.as_ref() else {
        return Err("the manifest declares no headless half".to_owned());
    };
    let wasm = std::fs::read(directory.join(&headless.artifact))
        .map_err(|error| format!("the artifact could not be read: {error}"))?;

    let grants = grants_of(&manifest)?;
    let policy = if headless.stateful { InstancePolicy::Stateful } else { InstancePolicy::Stateless };
    set.load(PluginSpec {
        id: id.clone(),
        version: manifest.version.clone(),
        wasm,
        grants,
        policy,
        limit: INSTANCE_LIMIT,
    })
    .map_err(|error| error.to_string())?;
    Ok(id)
}

/// The capability set a manifest asks for.
///
/// # Why this cannot fail silently
///
/// A manifest whose capability string does not parse is a manifest whose author asked for something the grammar has no
/// meaning for. Loading it with an empty set would grant it nothing and look like a working plugin that declined every
/// share — which is a bug report that sends the author looking in the wrong file entirely.
fn grants_of(manifest: &synra_plugin_api::Manifest) -> Result<CapabilitySet, String> {
    let mut grants = CapabilitySet::new();
    for declaration in &manifest.capabilities {
        grants.insert_str(&declaration.cap).map_err(|error| format!("`{}`: {error}", declaration.cap))?;
    }
    Ok(grants)
}
