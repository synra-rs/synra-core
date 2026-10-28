//! Loading the plugins a host is supposed to be running.
//!
//! # Why this lives in the kernel rather than in a host
//!
//! Because loading is the same decision in every host. The engine is a host's own — a windowless daemon and a Tauri shell
//! each bring one — but *which* installed plugins run, and with what authority, is the kernel's answer:
//! `PluginRow::should_run` says the user enabled and trusted it, `plugin_grants` says what they approved, the manifest on
//! disk says what version is there, and the revocation list says whether it may run at all. Two hosts that each assembled
//! those five facts would eventually disagree about one of them, and the disagreement would show up as "the same plugin
//! works in the daemon and not in the window".
//!
//! The daemon had this code first, in `apps/synra-daemon/src/runtime/plugins.rs`, and the desktop shell never had it —
//! so a plugin installed from the window was listed, could be enabled, and was never loaded. This module is that code
//! moved to the one place both hosts can call.
//!
//! # Why one plugin's failure does not stop the rest
//!
//! Because a machine with five plugins installed and one broken must still run the other four, and a host that refuses to
//! start because a single artifact is missing has turned a plugin's problem into a kernel's outage. So every plugin is
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
use synra_plugin_host::{CallBudget, CallOutcome, InstancePolicy, Work};
use synra_protocol::ids::PluginId;

use synra_observe::crash::StartupVerdict;

use crate::dispatch::{PluginSet, PluginSpec};

mod discovery;

pub use discovery::{Discovered, record_discovered_plugins};

/// How many instances one plugin may have.
///
/// # Why this is a constant here rather than in the manifest
///
/// Because the manifest's `resourceHints` are, by name, hints — soft, and ignorable. A host that took its limit from a
/// string a plugin author wrote would be taking its resource ceiling from third-party code. Four is the point where a
/// plugin stops being concurrent and starts being a memory leak with a licence.
pub const INSTANCE_LIMIT: u32 = 4;

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
    /// Why nothing was loaded at all, when the host chose not to start plugins.
    ///
    /// `Some` only in safe mode. It is a separate field rather than an entry in `refused` because the two are different
    /// statements: `refused` names plugins that failed, and this names a decision the host made before looking at any
    /// of them. Putting it in `refused` would attribute the refusal to a plugin that was never examined.
    pub safe_mode: Option<String>,
}

impl LoadedSummary {
    /// How many plugins this host can now ask.
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

    /// Why a plugin of this identifier was not loaded, when it was examined and failed.
    #[must_use]
    pub fn refusal_for(&self, plugin_id: &str) -> Option<&str> {
        self.refused
            .iter()
            .find(|refused| refused.plugin_id == plugin_id)
            .map(|refused| refused.reason.as_str())
    }

    /// Records a plugin as loaded, replacing any earlier refusal for it.
    ///
    /// Used by a host after it loads one plugin on demand — an enable, an update — so the report it shows stays the
    /// same record the startup pass wrote rather than a second, partial answer.
    pub fn record_loaded(&mut self, id: PluginId) {
        self.refused.retain(|refused| refused.plugin_id != id.as_str());
        if !self.loaded.contains(&id) {
            self.loaded.push(id);
        }
    }

    /// Records a plugin as refused, replacing any earlier "loaded" claim for it.
    pub fn record_refused(&mut self, plugin_id: &str, reason: String) {
        self.loaded.retain(|id| id.as_str() != plugin_id);
        self.refused.retain(|refused| refused.plugin_id != plugin_id);
        self.refused.push(Refused { plugin_id: plugin_id.to_owned(), reason });
    }

    /// Forgets a plugin entirely, for a host that has just unloaded or removed it.
    ///
    /// A disabled plugin is neither loaded nor refused — it is a decision the user made — so both lists have to let it
    /// go. Leaving the loaded claim behind is what makes a later "why is this not running" answer with a stale reason.
    pub fn record_unloaded(&mut self, id: &PluginId) {
        self.loaded.retain(|loaded| loaded != id);
        self.refused.retain(|refused| refused.plugin_id != id.as_str());
    }
}

/// Loads every plugin the database says should run.
///
/// A row that is not [`synra_store::PluginRow::should_run`] is not loaded and not refused: the user switched it off or
/// never trusted it, and that is a decision already made rather than something that went wrong here.
///
/// # ★ Why the verdict is a parameter
///
/// Because safe mode has to be able to stop this. `StartupVerdict::allows_plugins` existed, was tested, and was **called
/// only from tests** — no plugin-loading path asked it. So a plugin that crashed on activation three times in a row would
/// crash a fourth and a fifth time, and the settings screen the user needs to disable it stayed unreachable. The verdict's
/// own doc comment says that reaching the settings screen is "the only outcome that has to exist"; the code that reaches
/// it did not exist.
///
/// Taking the verdict rather than a `bool` is deliberate: a refusal can then say *which* location has been crashing,
/// which is the sentence a user needs to act on.
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
///
/// # ★ Why the config is a parameter rather than read here
///
/// The host snapshots its environment once for the pass. The loader owns each short database read and releases its
/// guard before filesystem work, engine compilation and guest activation, whose host calls may use the same store.
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
        // Nothing is loaded and nothing is refused per plugin: this is not a fault in any one plugin's artifact, it is
        // the host choosing not to start them at all. Recorded on the summary so the interface can say so instead of
        // showing an empty list, which would read as "nothing is installed".
        summary.safe_mode = Some(verdict.explain());
        return summary;
    }

    let Ok(rows) = db.lock().plugins() else {
        // The table being unreadable is the host's problem, and it is reported through its own status line; here it
        // means "nothing could be loaded" rather than "nothing is installed".
        return summary;
    };

    for row in rows {
        if !row.should_run() {
            continue;
        }
        match load_plugin_with_config(set, db, plugins_dir, &row.plugin_id, revocations, activation) {
            Ok(id) => summary.loaded.push(id),
            Err(reason) => summary.refused.push(Refused { plugin_id: row.plugin_id.clone(), reason }),
        }
    }
    summary
}

/// Loads one plugin from its directory, whether or not the database says it should run.
///
/// The caller decides *whether*; this function decides *how*, and it refuses rather than loading a plugin whose consent
/// does not match the document on disk. That split is what lets an enable load the one plugin it just switched on without
/// re-running the whole pass.
///
/// # Errors
///
/// A string saying what stopped it, because every reason here is a fact about a file on disk or a manifest a third party
/// wrote, and each one is something the user or the author needs to read rather than an error code to map elsewhere.
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
///
/// The caller passes the shared mutex, never a held database guard. Guest activation can call back into the store.
pub fn load_plugin_with_config(
    set: &mut PluginSet,
    db: &parking_lot::Mutex<synra_store::SynraDb>,
    plugins_dir: &Path,
    plugin_id: &str,
    revocations: &synra_plugin_api::revocation::RevocationList,
    activation: &str,
) -> Result<PluginId, String> {
    let id = PluginId::try_from(plugin_id.to_owned()).map_err(|error| format!("the id is not usable: {error}"))?;
    // ★ The **sanitised** directory name, which is the one the installer writes.
    //
    // A scoped id contains a separator, so joining it raw looked under `plugins/@acme/hello` — two levels the installer
    // never creates, because it writes `plugins/acme+hello` (the same name `Paths::plugin_dir`, removal, the sweep and
    // the data sandbox use). The daemon's tests wrote the raw path by hand, so they passed while every installed plugin
    // failed to load. One function decides this name for everybody.
    let directory = plugins_dir.join(synra_store::sanitise_component(plugin_id));
    let manifest_text = std::fs::read_to_string(directory.join("manifest.json"))
        .map_err(|error| format!("the manifest could not be read: {error}"))?;
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("the manifest is not readable: {error}"))?;

    // ★ The revocation list, checked **before** anything else about the plugin is considered.
    //
    // The design's behaviour for an installed revoked version is "disable immediately, and tell the user". Two things follow
    // that are not obvious:
    //
    // 1. **The disable is written to the store, not just skipped here.** Refusing to load it this run would leave it enabled,
    //    so the next start tries again — and a revocation that has to be re-discovered on every boot is one that is
    //    re-decided on every boot.
    // 2. **It comes before the grants.** A plugin that is revoked *and* unconfirmed is still revoked, and reporting the
    //    missing consent would send its author looking for a permission problem.
    if let Some(reason) = revocations.revokes(plugin_id, &manifest.version) {
        let now = synra_store::sqlite::now_ms();
        if let Err(error) = db.lock().set_plugin_enabled(plugin_id, false, now) {
            // Reported rather than swallowed: the plugin is not loaded either way, but a user whose store refused the write
            // will see it enabled again next start, and that is a thing they need to be told.
            eprintln!("synra: {plugin_id} is revoked and could not be disabled in the store: {error}");
        }
        return Err(format!("it is revoked and has been disabled: {reason}"));
    }

    let Some(headless) = manifest.runtime.headless.as_ref() else {
        return Err("the manifest declares no headless half".to_owned());
    };
    let wasm = std::fs::read(directory.join(&headless.artifact))
        .map_err(|error| format!("the artifact could not be read: {error}"))?;

    // ★ The grants are what the **user approved**, not what the manifest asks for.
    //
    // This was `grants_of(&manifest)`, which made the plugin's own declaration its authorisation: the consent table had
    // no writer, so there was nothing else to consult. A plugin received exactly what it asked for and the per-capability
    // consent the whole capability model rests on did not exist at either end.
    //
    // # Why a mismatch is a refusal rather than an intersection
    //
    // Because intersecting quietly would be the wrong shape for the common case. A plugin whose manifest has changed —
    // an update that adds a capability — has decisions recorded against a *different document*, and the honest answer is
    // "we need to ask again", not "we will run it with less than it says it needs". The second one produces a plugin
    // that appears to work and fails at one thing, which is exactly the silent degradation consent exists to prevent.
    //
    // The digest is over the bytes on disk, so a manifest that was edited rather than replaced is caught too.
    let digest = synra_plugin_api::manifest_digest(&manifest_text);
    let decisions = db
        .lock()
        .plugin_grants(plugin_id)
        .map_err(|error| format!("the decisions could not be read: {error}"))?;
    if decisions.is_empty() && !manifest.capabilities.is_empty() {
        // Trusted with nothing recorded is the state a pre-consent build left behind, and it is not an authorisation.
        return Err("it has not been confirmed by the user".to_owned());
    }
    if decisions.iter().any(|decision| decision.manifest_digest != digest) {
        return Err("it has changed since the user confirmed it, and needs confirming again".to_owned());
    }

    let grants = granted_of(&decisions)?;
    // ★ "Granted" is not "granted everything". A decision row that says no is what makes the lifecycle's
    // `partially_denied` true, and the state machine records it rather than inferring it from a later call refusal.
    let partially_denied = decisions.iter().any(|decision| !decision.granted);
    let policy = if headless.stateful { InstancePolicy::Stateful } else { InstancePolicy::Stateless };
    // The documented default allowance. A manifest does not declare a quota yet, so there is nothing more specific to
    // take it from — and a number invented here would be a limit the plugin's author never agreed to.
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

    // ★ Loading is not activation. The design's `enable` is *activating*: compile, then call the plugin's own
    // `activate(config)`, and only then is it fit to answer. A plugin that compiles but refuses to start is not a
    // working plugin, and leaving it in the set would make it match a share it cannot execute.
    let config = activation.to_owned();
    let now = u64::try_from(synra_store::sqlite::now_ms()).unwrap_or(0);
    if let Err(reason) = activate(set, &id, &quota, now, &config) {
        // The compiled form is dropped: a plugin that failed to activate must not be left half-live in the set. The
        // reason is what the caller records, so the card says why rather than "unavailable".
        set.unload(&id);
        return Err(format!("it loaded but did not activate: {reason}"));
    }
    // ★ The last rung. Without this the set would say every loaded plugin is merely `Granted`, which is exactly the
    // state a plugin that refused `activate` would have — and the difference is the one the user needs to see.
    set.mark_active(&id).map_err(|error| {
        set.unload(&id);
        error.to_string()
    })?;
    Ok(id)
}

/// Calls one plugin's `activate` again on a set that still holds it.
///
/// # Why this exists
///
/// A faulted plugin used to be retried by unloading and loading it, which throws away the compiled artifact and the
/// lifecycle record just to reach the same activation. Clearing the fault and calling `activate` is the same user
/// action without pretending the plugin was never loaded.
///
/// # Errors
///
/// A sentence when the plugin is not loaded, when its `activate` refuses, or when the lifecycle will not record the
/// activation. The caller still owns the decision to unload on failure.
pub fn reactivate_loaded(
    set: &mut PluginSet,
    id: &PluginId,
    activation: &str,
    now_ms: u64,
) -> Result<(), String> {
    let quota = set.quota(id).ok_or_else(|| "it is not loaded, so there is nothing to re-activate".to_owned())?;
    activate(set, id, &quota, now_ms, activation)?;
    set.mark_active(id).map_err(|error| error.to_string())
}

/// The JSON a plugin receives in `activate`.
///
/// # Why these two fields and not an empty object
///
/// Because the contract gives `activate` a JSON string and the SDK's own example reads `config.locale`. The host already
/// knows both answers — [`synra_plugin_host::Host::locale`] and `dark_mode` — so passing `{}` was withholding facts the
/// plugin otherwise has to make a second call for. There is no per-plugin settings store yet; when there is, it belongs
/// in this object beside them, and this is the one function that changes.
#[must_use]
pub fn activation_config(host: &dyn synra_plugin_host::Host) -> String {
    serde_json::json!({
        "locale": host.locale(),
        "darkMode": host.dark_mode(),
    })
    .to_string()
}

/// Calls one plugin's `activate` with the budget its quota allows.
///
/// # Why the config is passed in
///
/// Because the caller is the one that can see the host's environment ([`activation_config`]), and a function that built
/// its own would be a second answer to "what locale is this host in". The contract passes the JSON through; per-plugin
/// settings, when a table exists for them, belong in that object rather than in a second parameter here.
///
/// # Errors
///
/// The plugin's own refusal, a trap, or a budget the call could not start under. All three mean "not fit to answer", and
/// the loader records the sentence rather than guessing which kind it was.
fn activate(
    set: &mut PluginSet,
    id: &PluginId,
    quota: &synra_plugin_host::quota::Quota,
    now_ms: u64,
    config_json: &str,
) -> Result<(), String> {
    let work = Work::Activate { config_json: config_json.to_owned() };
    match set.call(id, &work, CallBudget::from_quota(quota), now_ms) {
        Ok(CallOutcome::Ok(_)) => Ok(()),
        // The plugin handled the call and said no. Its message is the one its author wrote for exactly this moment.
        Ok(CallOutcome::Failed { message, .. }) => Err(format!("its activate refused: {message}")),
        Ok(other) => Err(format!("its activate {}", other.as_str())),
        Err(error) => Err(error.to_string()),
    }
}

/// Asks one plugin to bring its own data forward, before the new version is written.
///
/// # Why this runs on the **old** instance
///
/// Because the data being migrated is the old plugin's, and the old code is the only code that knows what it wrote. The
/// new artifact is not on disk yet, so a migration failure leaves the old version installed and running — which is the
/// only outcome a user can act on. Running it after the replacement would mean the bytes that wrote the data are already
/// gone, and a refusal would have nothing to fall back to.
///
/// # Errors
///
/// The plugin's own refusal, a trap, a budget that could not be granted, or the plugin not being loaded. The caller turns
/// this into a refusal of the update rather than writing the new version.
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
    match set.call(id, &work, CallBudget::from_quota(&synra_plugin_host::quota::Quota::default()), now_ms) {
        Ok(CallOutcome::Ok(_)) => Ok(()),
        Ok(CallOutcome::Failed { message, .. }) => Err(format!("its migrate refused: {message}")),
        Ok(other) => Err(format!("its migrate {}", other.as_str())),
        Err(error) => Err(error.to_string()),
    }
}

/// Deactivates and unloads one plugin.
///
/// # Why a plugin that will not deactivate is still unloaded
///
/// Because the host cannot do better: the contract's `deactivate` returns nothing, and a guest that traps on the way out
/// has already lost the right to hold its instance. Dropping the compiled form is what actually releases the memory, so
/// the call is a courtesy with a budget rather than a step whose failure blocks the removal.
pub fn deactivate(set: &mut PluginSet, id: &PluginId, now_ms: u64) {
    let work = Work::Deactivate;
    // A short exchange: the plugin is releasing what it holds, not doing work for a user. The default quota's call
    // budget is what the contract gives every call, so this is the same bound a lifecycle call would get anywhere else.
    let _ = set.call(id, &work, CallBudget::from_quota(&synra_plugin_host::quota::Quota::default()), now_ms);
    set.unload(id);
}

/// The capability set the user granted, from the decisions on record.
///
/// # Why only the granted rows, and why a parse failure is loud
///
/// A denied row is a decision too, and it must not become a grant. And a capability string that does not parse is a row
/// that cannot be honoured: skipping it would run the plugin with less than the user approved, which looks exactly like
/// a plugin that declines everything — and sends its author looking in the wrong file.
fn granted_of(decisions: &[synra_store::PluginGrantRow]) -> Result<CapabilitySet, String> {
    let mut grants = CapabilitySet::new();
    for decision in decisions.iter().filter(|decision| decision.granted) {
        grants
            .insert_str(&decision.capability)
            .map_err(|error| format!("a granted capability is not usable: `{}`: {error}", decision.capability))?;
    }
    Ok(grants)
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
