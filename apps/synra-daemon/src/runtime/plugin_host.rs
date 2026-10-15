//! What a plugin's host calls reach, in the daemon.
//!
//! # Why this exists
//!
//! Because a plugin could not reach a host function at all. `instantiate` left every instance with no session, and
//! `linker::run` refuses **every** host call when there is no session — so the capability gate, the mechanism the whole
//! capability model rests on, never ran, and nothing was ever audited. The gate is only reachable once a `Host` exists to
//! hand a session, and this is the daemon's.
//!
//! # What it serves, and what it refuses
//!
//! The rule is that a function is answered when this host genuinely knows the answer, and refused with a code when it
//! does not. Refusing is not a placeholder: a plugin branches on the code, and `NOT_IMPLEMENTED` is a fact it can act on.
//! Inventing a plausible answer is the one thing that would be worse than refusing, because a plugin cannot tell an
//! invented answer from a real one.
//!
//! | Group | Served | Why |
//! | --- | --- | --- |
//! | environment | `sdk-version`, `host-kind`, `locale`, `dark-mode`, `can`, `plugin-id` | the values exist here |
//! | logging | `log` | `tracing`, which the daemon already writes |
//! | devices | `devices` | the transport's own registry |
//! | everything else | refused | storage, secrets, network, transfer and platform are not implemented in this build |
//!
//! # The one place the contract cannot say "I do not know"
//!
//! `platform_capabilities`, `locale` and `dark_mode` return values rather than `Result`, so there is no way for this host
//! to refuse. It answers `platform_capabilities` with an empty list — the daemon has no platform integration, and a list
//! of nothing is at least true — and reads the other two from the configuration, falling back to the value a fresh
//! installation has. That is a **contract limitation** rather than a decision: an infallible question cannot distinguish
//! "no answer" from "none", and a plugin has no way to tell either.

use std::sync::Arc;

use parking_lot::Mutex;
use synra_plugin_host::host_calls::{CallError, Host};
use synra_protocol::ids::PluginId;

/// The daemon's answer to a plugin's host calls.
pub(super) struct KernelHost {
    /// The database, for the two questions that are answered from what is recorded: which capabilities the user granted,
    /// and what the interface was configured with.
    db: Arc<Mutex<synra_store::SynraDb>>,
    /// The version a plugin is told it was built against.
    version: String,
}

impl KernelHost {
    /// A host over the daemon's own state.
    #[must_use]
    pub(super) fn new(db: Arc<Mutex<synra_store::SynraDb>>, version: impl Into<String>) -> Self {
        Self { db, version: version.into() }
    }

    /// A configuration value, which the store keeps as JSON text.
    fn setting(&self, key: &str) -> Option<String> {
        let rows = self.db.lock().config().ok()?;
        rows.into_iter().find(|row| row.key == key).map(|row| row.value)
    }

    /// The capabilities the user granted this plugin, as the database records them.
    ///
    /// # Why this reads the consent table rather than the loader's `CapabilitySet`
    ///
    /// Because the two are the same set for the same reason — the loader takes its grants from the user's decisions —
    /// and the table is what this process can reach. `env-can` is a question a plugin asks about **itself**, so the
    /// answer has to agree with the gate that will judge its calls; reading the same source is what makes that true
    /// rather than merely likely.
    fn granted(&self, plugin: &PluginId) -> Vec<String> {
        self.db
            .lock()
            .plugin_grants(plugin.as_str())
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.granted)
            .map(|row| row.capability)
            .collect()
    }
}

/// The refusal this host gives for everything it does not implement.
///
/// One code, one sentence, naming the group rather than the function: a plugin author who reads "storage is not
/// implemented in this build" knows to design around it, and one who reads "storage-get failed" does not.
fn not_implemented(group: &str) -> CallError {
    CallError::new(
        "NOT_IMPLEMENTED",
        &format!("this host does not implement {group}"),
    )
}

impl Host for KernelHost {
    fn sdk_version(&self) -> String {
        self.version.clone()
    }

    fn host_kind(&self) -> String {
        // The daemon has no window, which is the whole of what it is. `desktop` would be a claim about a surface this
        // process does not have.
        "headless".to_owned()
    }

    fn locale(&self) -> String {
        // See the module doc: an infallible question cannot say "I do not know". The interface's own setting is the
        // honest source, and a fresh installation has none.
        self.setting("ui.locale")
            .and_then(|value| serde_json::from_str::<String>(&value).ok())
            .unwrap_or_default()
    }

    fn dark_mode(&self) -> bool {
        self.setting("ui.darkMode")
            .and_then(|value| serde_json::from_str::<bool>(&value).ok())
            .unwrap_or(false)
    }

    fn can(&self, plugin: &PluginId, capability: &str) -> bool {
        // The same matching the gate uses: a grant of `log:*` covers `log:info`. A string comparison would make the two
        // spellings different capabilities, and a plugin would be told it cannot do what the gate will let it do.
        let Ok(needed) = synra_capability::Capability::parse(capability) else {
            return false;
        };
        let mut held = synra_capability::CapabilitySet::new();
        for text in self.granted(plugin) {
            let _ = held.insert_str(&text);
        }
        held.grants(&needed)
    }

    fn platform_capabilities(&self) -> Vec<String> {
        // Empty rather than invented. This build has no platform integration, so there is nothing it can promise, and a
        // list of plausible names would be a promise a plugin could build a feature on.
        Vec::new()
    }

    fn log(
        &self,
        plugin: &PluginId,
        level: &str,
        message: &str,
        context: Option<&str>,
    ) -> Result<(), CallError> {
        // Through `tracing`, which is where the daemon's own record goes — so a plugin's line lands in the same file as
        // everything else and a user has one place to look. The plugin is a field rather than part of the message,
        // because a reader filtering the log wants to filter by it.
        match level {
            "trace" => tracing::trace!(plugin = plugin.as_str(), context, "{message}"),
            "debug" => tracing::debug!(plugin = plugin.as_str(), context, "{message}"),
            "warn" => tracing::warn!(plugin = plugin.as_str(), context, "{message}"),
            "error" => tracing::error!(plugin = plugin.as_str(), context, "{message}"),
            _ => tracing::info!(plugin = plugin.as_str(), context, "{message}"),
        }
        Ok(())
    }

    fn devices(&self) -> Vec<(String, String, String)> {
        // ★ What this side can actually reach, not everything it has ever paired with.
        //
        // A device that is paired but unreachable is one a send would fail against, and offering it turns a list into a
        // promise. `is_usable` is the same test the interface's own device list applies, so a plugin sees the set a user
        // sees rather than a wider one it cannot act on.
        //
        // Read from the database rather than from the transport's live registry: the two hold the same rows, and the
        // database is the one a plugin's question can be answered from without depending on whether the network
        // happened to start.
        let rows = self.db.lock().paired_devices().unwrap_or_default();
        rows.iter()
            .filter(|device| device.is_usable())
            .map(|device| {
                (device.device_id.clone(), device.display_name.clone(), device.platform.clone())
            })
            .collect()
    }

    fn event_emit(&self, _p: &PluginId, _e: &str, _payload: &str) -> Result<(), CallError> {
        Err(not_implemented("event emission"))
    }

    fn device_send(&self, _p: &PluginId, _t: &str, _e: &str, _pl: &str) -> Result<(), CallError> {
        Err(not_implemented("device sends"))
    }

    fn device_broadcast(&self, _p: &PluginId, _e: &str, _pl: &str) -> Result<(), CallError> {
        Err(not_implemented("device broadcasts"))
    }

    fn storage_get(&self, _p: &PluginId, _k: &str) -> Result<Option<String>, CallError> {
        Err(not_implemented("plugin storage"))
    }

    fn storage_set(&self, _p: &PluginId, _k: &str, _v: &str) -> Result<(), CallError> {
        Err(not_implemented("plugin storage"))
    }

    fn storage_delete(&self, _p: &PluginId, _k: &str) -> Result<(), CallError> {
        Err(not_implemented("plugin storage"))
    }

    fn storage_keys(&self, _p: &PluginId, _prefix: Option<&str>) -> Result<Vec<String>, CallError> {
        Err(not_implemented("plugin storage"))
    }

    fn storage_quota(&self, _p: &PluginId) -> Result<(u64, u64), CallError> {
        Err(not_implemented("plugin storage"))
    }

    fn secret_get(&self, _p: &PluginId, _k: &str) -> Result<Option<String>, CallError> {
        Err(not_implemented("secrets"))
    }

    fn secret_set(&self, _p: &PluginId, _k: &str, _v: &str) -> Result<(), CallError> {
        Err(not_implemented("secrets"))
    }

    fn secret_delete(&self, _p: &PluginId, _k: &str) -> Result<(), CallError> {
        Err(not_implemented("secrets"))
    }

    fn fetch(&self, _p: &PluginId, _request_json: &str) -> Result<String, CallError> {
        // No HTTP client exists anywhere in this workspace, which is a fact rather than an omission here — see the
        // design document's note on `network.fetch`.
        Err(not_implemented("network access"))
    }

    fn transfer_send(&self, _p: &PluginId, _k: &str, _t: &str, _m: &str) -> Result<String, CallError> {
        Err(not_implemented("transfers"))
    }

    fn transfer_status(&self, _p: &PluginId, _id: &str) -> Result<String, CallError> {
        Err(not_implemented("transfers"))
    }

    fn platform(&self, _p: &PluginId, _a: &str, _arg: &str) -> Result<Option<String>, CallError> {
        Err(not_implemented("platform actions"))
    }

    fn action_declare(&self, _p: &PluginId, _n: &str, _s: &str) -> Result<(), CallError> {
        Err(not_implemented("actions"))
    }

    fn action_list(&self, _p: &PluginId) -> Result<String, CallError> {
        Err(not_implemented("actions"))
    }

    fn action_invoke(&self, _p: &PluginId, _t: &str, _n: &str, _a: &str) -> Result<String, CallError> {
        Err(not_implemented("actions"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use synra_plugin_host::host_calls::Host as _;
    use synra_protocol::ids::PluginId;

    use super::KernelHost;

    fn id(name: &str) -> PluginId {
        PluginId::try_from(name.to_owned()).expect("a plugin id")
    }

    fn host_with(grants: &[(&str, bool)]) -> KernelHost {
        let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
        db.migrate().expect("migrates");
        db.insert_plugin("@acme/notes", true, true, "healthy", 1, 1).expect("a plugin row");
        let decisions: Vec<(String, bool)> =
            grants.iter().map(|(cap, granted)| ((*cap).to_owned(), *granted)).collect();
        db.record_grants("@acme/notes", &decisions, 1, "digest").expect("decisions");
        KernelHost::new(Arc::new(Mutex::new(db)), "9.9.9")
    }

    #[test]
    fn can_answers_from_what_the_user_actually_granted() {
        // ★ `env-can` is a question a plugin asks about **itself**, so the answer has to agree with the gate that will
        // judge its calls. Reading the same consent table is what makes that true rather than merely likely.
        let host = host_with(&[("log:*", true), ("device:list", false)]);

        assert!(host.can(&id("@acme/notes"), "log:info"), "a granted wildcard covers the specific");
        assert!(!host.can(&id("@acme/notes"), "device:list"), "a denied capability is denied");
        assert!(!host.can(&id("@acme/notes"), "storage:local:read"), "and one never asked about");
        assert!(!host.can(&id("@acme/other"), "log:info"), "an unknown plugin holds nothing");
    }

    #[test]
    fn a_malformed_capability_is_not_a_grant() {
        // The gate parses before it matches, so a string that is not a capability cannot be held. Answering `true` here
        // would tell a plugin it may do something the gate would then refuse.
        let host = host_with(&[("log:*", true)]);
        assert!(!host.can(&id("@acme/notes"), "not a capability"));
        assert!(!host.can(&id("@acme/notes"), ""));
    }

    #[test]
    fn the_groups_this_build_does_not_implement_refuse_with_one_code() {
        // ★ Refusing is not a placeholder. A plugin branches on the code, and `NOT_IMPLEMENTED` says "this host cannot
        // do that" rather than "you are not allowed" — which is the difference between a plugin hiding a feature and a
        // user hunting for a permission they already granted.
        let host = host_with(&[]);
        let plugin = id("@acme/notes");

        for refusal in [
            host.event_emit(&plugin, "x", "{}"),
            host.device_send(&plugin, "d", "x", "{}"),
            host.storage_get(&plugin, "k").map(|_| ()),
            host.secret_get(&plugin, "k").map(|_| ()),
            host.fetch(&plugin, "{}").map(|_| ()),
            host.transfer_status(&plugin, "t").map(|_| ()),
            host.platform(&plugin, "a", "{}").map(|_| ()),
            host.action_list(&plugin).map(|_| ()),
        ] {
            let error = refusal.expect_err("this build does not implement it");
            assert_eq!(error.code, "NOT_IMPLEMENTED", "{error:?}");
        }
    }

    #[test]
    fn the_answers_that_exist_are_the_daemons_own() {
        let host = host_with(&[]);

        assert_eq!(host.sdk_version(), "9.9.9", "the version this host was built at");
        assert_eq!(host.host_kind(), "headless", "the daemon has no window, and saying desktop would be a claim");
        // ★ Empty rather than invented. A list of plausible platform capabilities would be a promise a plugin could
        // build a feature on, and this build has no platform integration to keep it.
        assert!(host.platform_capabilities().is_empty());
        // A fresh database has paired with nothing, so the list is empty — and it is empty because it is true.
        assert!(host.devices().is_empty());
    }
}
