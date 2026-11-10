//! Adapts the daemon's state and platform policies to the guest host contract.

use synra_plugin_host::host_calls::{CallError, Host, PlatformAction};
use synra_protocol::ids::PluginId;

use super::{KernelHost, network::fetcher_for};

/// The refusal this host gives for everything it does not implement.
///
/// One code, one sentence, naming the group rather than the function: a plugin author who reads "storage is not
/// implemented in this build" knows to design around it, and one who reads "storage-get failed" does not.
fn not_implemented(group: &str) -> CallError {
    // ★ The code comes from `CallError` rather than being spelled here. This host invented `"NOT_IMPLEMENTED"` — upper
    // case with an underscore, when every code the contract defines is camelCase — so a plugin branching on the documented
    // spelling would have matched nothing.
    CallError::new(
        CallError::NOT_IMPLEMENTED,
        format!("this host does not implement {group}"),
    )
}

/// A store failure, as the plugin sees it.
///
/// # Why `hostFailed` rather than something more specific
///
/// Because the plugin did nothing wrong: a locked database or a full disk is the host's problem, and the code tells the
/// plugin not to retry the same call in a loop. The underlying message goes in the sentence, where a log line can use it
/// even though a plugin cannot act on it.
fn failed(what: &str, error: &impl std::fmt::Display) -> CallError {
    CallError::new(CallError::HOST_FAILED, format!("could not {what}: {error}"))
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
        //
        // ★ The action's trace is a field too, when the call is part of one. It is read from the thread's scope rather than
        // passed in: the plugin contract has no place for a trace, and `PluginSet::call_traced` makes it current for the
        // duration of the call. `synra logs --trace <id>` therefore shows the plugin's own lines as well as the kernel's.
        let trace = synra_observe::trace_scope::current();
        match trace {
            Some(trace) => match level {
                "trace" => tracing::trace!(plugin = plugin.as_str(), context, trace_id = %trace, "{message}"),
                "debug" => tracing::debug!(plugin = plugin.as_str(), context, trace_id = %trace, "{message}"),
                "warn" => tracing::warn!(plugin = plugin.as_str(), context, trace_id = %trace, "{message}"),
                "error" => tracing::error!(plugin = plugin.as_str(), context, trace_id = %trace, "{message}"),
                _ => tracing::info!(plugin = plugin.as_str(), context, trace_id = %trace, "{message}"),
            },
            None => match level {
                "trace" => tracing::trace!(plugin = plugin.as_str(), context, "{message}"),
                "debug" => tracing::debug!(plugin = plugin.as_str(), context, "{message}"),
                "warn" => tracing::warn!(plugin = plugin.as_str(), context, "{message}"),
                "error" => tracing::error!(plugin = plugin.as_str(), context, "{message}"),
                _ => tracing::info!(plugin = plugin.as_str(), context, "{message}"),
            },
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

    fn event_emit(&self, plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError> {
        self.events.emit_call(plugin, event, payload)
    }

    fn device_send(&self, _p: &PluginId, _t: &str, _e: &str, _pl: &str) -> Result<(), CallError> {
        Err(not_implemented("device sends"))
    }

    fn device_broadcast(&self, _p: &PluginId, _e: &str, _pl: &str) -> Result<(), CallError> {
        Err(not_implemented("device broadcasts"))
    }

    fn storage_get(&self, plugin: &PluginId, key: &str) -> Result<Option<String>, CallError> {
        self.db
            .lock()
            .storage_get(plugin.as_str(), key)
            .map_err(|error| failed("read the plugin's storage", &error))
    }

    fn storage_set(&self, plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError> {
        // ★ The quota is **not** checked here, and that is deliberate.
        //
        // A plugin's storage ceiling is part of its quota, the quota is what the call budget in `HostCalls` was built
        // from, and that layer checks it before this is reached. A second check here would need a limit this host does not
        // have — and a host that invented one would be the second source that the trait's `storage_used` exists to avoid.
        self.db
            .lock()
            .storage_set(plugin.as_str(), key, value, synra_store::sqlite::now_ms())
            .map_err(|error| failed("write the plugin's storage", &error))
    }

    fn storage_delete(&self, plugin: &PluginId, key: &str) -> Result<(), CallError> {
        self.db
            .lock()
            .storage_delete(plugin.as_str(), key)
            .map_err(|error| failed("remove the plugin's storage", &error))?;
        Ok(())
    }

    fn storage_keys(&self, plugin: &PluginId, prefix: Option<&str>) -> Result<Vec<String>, CallError> {
        self.db
            .lock()
            .storage_keys(plugin.as_str(), prefix)
            .map_err(|error| failed("list the plugin's storage", &error))
    }

    fn storage_used(&self, plugin: &PluginId) -> Result<u64, CallError> {
        self.db
            .lock()
            .storage_used_bytes(plugin.as_str())
            .map_err(|error| failed("measure the plugin's storage", &error))
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

    fn fetch(&self, plugin: &PluginId, request_json: &str) -> Result<String, CallError> {
        let client = fetcher_for(self, plugin)?;
        client.fetch_plugin(request_json, &self.granted(plugin))
    }

    fn transfer_send(&self, _p: &PluginId, _k: &str, _t: &str, _m: &str) -> Result<String, CallError> {
        Err(not_implemented("transfers"))
    }

    fn transfer_status(&self, _p: &PluginId, _id: &str) -> Result<String, CallError> {
        Err(not_implemented("transfers"))
    }

    fn platform(
        &self,
        _plugin: &PluginId,
        action: PlatformAction,
        argument: &str,
    ) -> Result<Option<String>, CallError> {
        use synra_platform::Platform as _;
        // The shared dispatcher supplies a typed action; this adapter applies the headless platform's policy.
        let refusal = |error: synra_platform::PlatformError| CallError::new(
            match error {
                // ★ A refused address, path or chord is `badArgument`: the plugin supplied it, and telling it so is the
                // whole reason the guard runs before the refusal.
                synra_platform::PlatformError::BadUrl { .. }
                | synra_platform::PlatformError::BadPath { .. }
                | synra_platform::PlatformError::TooLong { .. }
                | synra_platform::PlatformError::SimulateKeysNotGranted => CallError::BAD_ARGUMENT,
                // And "this build has no browser" is `notImplemented`, which is a different fact about a different
                // party: the first is the plugin's to fix, the second is the installation's.
                synra_platform::PlatformError::Unsupported(_)
                | synra_platform::PlatformError::Unavailable(_) => CallError::NOT_IMPLEMENTED,
                // The rest are the host's own state rather than the plugin's argument: too soon after the last action,
                // over its rate, out of quota. `hostFailed` is what a plugin retries on.
                synra_platform::PlatformError::NoRecentInteraction { .. }
                | synra_platform::PlatformError::RateLimited { .. }
                | synra_platform::PlatformError::QuotaExceeded { .. } => CallError::HOST_FAILED,
                // `PlatformError` is `#[non_exhaustive]`, so a variant added later lands here. `hostFailed` is the
                // honest default: this build does not know what the new refusal means, and telling a plugin its argument
                // was wrong when the fault may be the host's would be worse than a code it simply retries on.
                _ => CallError::HOST_FAILED,
            },
            error.to_string(),
        );

        let outcome = match action {
            PlatformAction::OpenUrl => self.platform.open_url(argument),
            PlatformAction::OpenPath => self.platform.open_path(std::path::Path::new(argument)),
            PlatformAction::RevealPath => self
                .platform
                .reveal_path(std::path::Path::new(argument), None),
            PlatformAction::SimulateKeys => self.platform.simulate_keys(argument),
            PlatformAction::ReadClipboard => {
                return self.platform.read_clipboard().map_err(refusal);
            }
            PlatformAction::WriteClipboard => self.platform.write_clipboard(argument),
            PlatformAction::Notify => {
                // A notification carries a title and a body separated by the contract's own delimiter — the same shape
                // `host_calls` builds when it sends one.
                let (title, body) = argument.split_once('\u{1}').unwrap_or((argument, ""));
                self.platform.notify(title, body)
            }
            _ => {
                return Err(CallError::new(
                    CallError::NOT_IMPLEMENTED,
                    "this daemon does not implement this platform action",
                ));
            }
        };
        // `Ok` is unreachable for a headless host by construction — every method refuses after checking — and it is still
        // handled rather than assumed, because a host that later performs the action must not need this match rewritten.
        match outcome {
            Ok(()) => Ok(None),
            Err(error) => Err(refusal(error)),
        }
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
