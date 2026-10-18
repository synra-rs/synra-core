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

/// One plugin's fetcher, and the hosts it was built for.
///
/// ★ A name rather than the type written out at the field: the tuple means "this client, for exactly these hosts", and
/// spelling it inline made the field the most complicated thing in the struct. The alias lets the field's doc say *why* the
/// host list is stored beside the client instead of a reader having to reconstruct it from a nested generic.
type FetchClients = Mutex<std::collections::HashMap<PluginId, (Vec<String>, Arc<synra_fetch::Client>)>>;

/// The daemon's answer to a plugin's host calls.
pub(crate) struct KernelHost {
    /// What this machine can do with a URL, a path or a notification.
    ///
    /// ★ Why the *host* answers this rather than a blanket refusal.
    ///
    /// `HeadlessPlatform` runs the guard and then refuses, in that order, and its own doc says why: *"a plugin that
    /// supplied `javascript:` should be told its address is refused, not that this host has no browser. The first is a
    /// mistake the author can fix and the second is a fact about the installation."*
    ///
    /// This host used to answer every platform call with `notImplemented`, which is the second answer to the first
    /// question — so a plugin with a malformed URL was told the installation lacked a feature, and its author had
    /// nothing to act on. `synra-platform` had the right answer all along and no caller.
    platform: synra_platform::HeadlessPlatform,
    /// One fetcher per plugin, and the hosts it was built for.
    ///
    /// ★ Why a cache rather than one client per call
    ///
    /// Because a client holds the plugin's **in-flight count**, and a client built per call would start from zero every
    /// time — so `max_concurrent` would never refuse anything. The host list is stored beside it because the guard is built
    /// from the plugin's grants, and a user who withdraws a host must not keep reaching it through a cached client: when
    /// the list changes, the client is rebuilt.
    fetch_clients: FetchClients,
    /// The database, for the two questions that are answered from what is recorded: which capabilities the user granted,
    /// and what the interface was configured with.
    db: Arc<Mutex<synra_store::SynraDb>>,
    /// The version a plugin is told it was built against.
    version: String,
}

impl KernelHost {
    /// A host over the daemon's own state.
    #[must_use]
    pub(crate) fn new(db: Arc<Mutex<synra_store::SynraDb>>, version: impl Into<String>) -> Self {
        Self {
            db,
            version: version.into(),
            // The default policies: strict, and the ones a headless daemon should hold. Nothing configures them yet, and
            // the builders on `Policies` are how a caller would — a daemon that let a plugin widen its own allowances
            // would defeat the point of having them.
            platform: synra_platform::HeadlessPlatform::default(),
            fetch_clients: Mutex::new(std::collections::HashMap::new()),
        }
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
    // ★ The code comes from `CallError` rather than being spelled here. This host invented `"NOT_IMPLEMENTED"` — upper
    // case with an underscore, when every code the contract defines is camelCase — so a plugin branching on the documented
    // spelling would have matched nothing.
    CallError::new(
        CallError::NOT_IMPLEMENTED,
        format!("this host does not implement {group}"),
    )
}

/// The fetcher for one plugin, built or rebuilt from what the user has granted it.
///
/// # Errors
///
/// [`CallError`] with `capabilityDenied` when the plugin holds no `network:fetch:<host>` grant at all — which is a
/// different answer from "that host is not one of them", and the one a plugin author needs when nothing works.
fn fetcher_for(host: &KernelHost, plugin: &PluginId) -> Result<Arc<synra_fetch::Client>, CallError> {
    let hosts = granted_hosts(host, plugin);

    // ★ An empty list is refused rather than treated as "any host".
    //
    // `network:fetch:*` is how the **gate** spells the family, and a plugin can hold it; but a guard built from it would
    // have to mean "every host on the internet", which is exactly the capability an SSRF guard exists to make deliberate.
    // So a grant with no host in it reaches nothing, and the refusal says which spelling is needed.
    if hosts.is_empty() {
        return Err(CallError::new(
            // The capability code rather than a host one: the plugin holds **no** host, which is a configuration problem
            // whose answer is "ask the user for `network:fetch:<host>`" — and that is what `capabilityDenied` says.
            CallError::CAPABILITY_DENIED,
            format!("`{plugin}` holds no `network:fetch:<host>` grant, so there is nowhere it may fetch from"),
        ));
    }

    // ★ The lock is taken twice rather than held, and the reason is the client's construction: it is not work that needs the
    // map, and holding the map while building one would make every plugin's fetch wait behind whichever one happened to be
    // first. The cost is that two callers arriving together may each build a client and the later insert wins — which
    // splits the in-flight count between them for as long as the loser's client lives, a weaker limit rather than a wrong
    // one, and the alternative is a lock held across everything a plugin does.
    {
        let clients = host.fetch_clients.lock();
        if let Some((built_for, client)) = clients.get(plugin)
            && *built_for == hosts
        {
            return Ok(Arc::clone(client));
        }
    }

    let client = Arc::new(synra_fetch::Client::new(
        synra_core::network::NetworkGuard::for_hosts(&hosts),
        synra_fetch::Limits::default(),
    ));
    host.fetch_clients.lock().insert(plugin.clone(), (hosts, Arc::clone(&client)));
    Ok(client)
}

/// The hosts a plugin was granted for fetching.
///
/// # What is taken from a capability, and what is left
///
/// `network:fetch:api.github.com` names a host; `network:fetch:api.github.com:POST` names a host **and a method**, and the
/// method is not this host's to enforce — the client sends whatever method the plugin asked for, and the guard's job is
/// where the request goes. So the segment after the prefix is the host and the rest is ignored here.
///
/// A capability that is not `network:fetch:` prefixed, or whose host segment is empty or the literal `*`, contributes
/// nothing. `*` is the family spelling the gate uses and not a host.
fn granted_hosts(host: &KernelHost, plugin: &PluginId) -> Vec<String> {
    let mut hosts: Vec<String> = host
        .db
        .lock()
        .plugin_grants(plugin.as_str())
        .unwrap_or_default()
        .into_iter()
        .filter(|row| row.granted)
        .filter_map(|row| host_of(&row.capability))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The host a `network:fetch:` capability names, when it names one.
///
/// # Why `*` is not a host
///
/// Because it is how the **gate** spells the family: the generated table answers `network:fetch:*` for the whole group, and
/// a guard that read it as a hostname would be a guard for a machine literally called `*`. A grant that names no host
/// therefore grants no host, which is the fail-closed reading.
#[must_use]
fn host_of(capability: &str) -> Option<String> {
    let rest = capability.strip_prefix("network:fetch:")?;
    let host = rest.split(':').next().unwrap_or_default();
    if host.is_empty() || host == "*" {
        return None;
    }
    Some(host.to_owned())
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

    fn event_emit(&self, _p: &PluginId, _e: &str, _payload: &str) -> Result<(), CallError> {
        Err(not_implemented("event emission"))
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
        let request: synra_fetch::Request = serde_json::from_str(request_json).map_err(|error| {
            CallError::new(CallError::BAD_ARGUMENT, format!("the request is not readable: {error}"))
        })?;

        let client = fetcher_for(self, plugin)?;
        let response = client.fetch(&request).map_err(|refusal| {
            // The guard's codes are the contract's own, so they travel as they are: `hostNotAllowed` is what a plugin
            // branches on to try somewhere else, and `responseTooLarge` to ask for less.
            CallError::new(refusal.code.as_str(), refusal.message)
        })?;

        serde_json::to_string(&response).map_err(|error| {
            CallError::new(CallError::HOST_FAILED, format!("the answer could not be written: {error}"))
        })
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
        action: &str,
        argument: &str,
    ) -> Result<Option<String>, CallError> {
        use synra_platform::Platform as _;
        // The action names come from the contract, and the host maps them to the same enum the admission checks use, so
        // a name that is not one is a contract disagreement rather than a plugin mistake.
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
            "open-url" => self.platform.open_url(argument),
            "open-path" => self.platform.open_path(std::path::Path::new(argument)),
            "reveal-path" => self.platform.reveal_path(std::path::Path::new(argument), None),
            "simulate-keys" => self.platform.simulate_keys(argument),
            "read-clipboard" => self.platform.read_clipboard().map(|_| ()),
            "write-clipboard" => self.platform.write_clipboard(argument),
            "notify" => {
                // A notification carries a title and a body separated by the contract's own delimiter — the same shape
                // `host_calls` builds when it sends one.
                let (title, body) = argument.split_once('\u{1}').unwrap_or((argument, ""));
                self.platform.notify(title, body)
            }
            other => {
                return Err(CallError::new(
                    CallError::BAD_ARGUMENT,
                    format!("`{other}` is not a platform action"),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use synra_plugin_host::host_calls::Host as _;
    use synra_protocol::ids::PluginId;

    use super::{KernelHost, fetcher_for, host_of};

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
    fn a_capability_names_a_host_or_it_names_nothing() {
        // The parsing rule, on its own, because everything below depends on it being the fail-closed reading.
        assert_eq!(host_of("network:fetch:api.github.com").as_deref(), Some("api.github.com"));
        // A method qualifier is not part of the host: the guard decides *where*, and the method travels as sent.
        assert_eq!(host_of("network:fetch:api.github.com:POST").as_deref(), Some("api.github.com"));

        // ★ `*` is the family spelling the **gate** uses, not a hostname. Reading it as one would build a guard for a
        // machine literally called `*`, and reading it as "anything" would be the capability an SSRF guard exists to make
        // deliberate — so it names nothing.
        assert_eq!(host_of("network:fetch:*"), None);
        assert_eq!(host_of("network:fetch:"), None);
        assert_eq!(host_of("network:fetch"), None);
        assert_eq!(host_of("fs:read:/data/**"), None);
    }

    #[test]
    fn a_plugin_with_no_host_grant_is_told_which_spelling_it_needs() {
        // Nothing granted at all: `capabilityDenied`, because the answer is "ask the user", not "that host is not one of
        // them" — and a plugin author can act on the first.
        let host = host_with(&[]);
        let refused = fetcher_for(&host, &id("@acme/notes")).expect_err("no grant");

        assert_eq!(refused.code, synra_plugin_host::host_calls::CallError::CAPABILITY_DENIED);
        assert!(refused.message.contains("network:fetch:"), "and it says what to ask for: {}", refused.message);
    }

    #[test]
    fn a_family_grant_with_a_star_is_not_a_grant_to_reach_everything() {
        // ★ The whole point of the guard, at the host: `network:fetch:*` passes the **gate** — it is the family — and it
        // must not become "every host on the internet". So it reaches nothing.
        let host = host_with(&[("network:fetch:*", true)]);
        let refused = fetcher_for(&host, &id("@acme/notes")).expect_err("no host named");

        assert_eq!(refused.code, synra_plugin_host::host_calls::CallError::CAPABILITY_DENIED, "{refused}");
    }

    #[test]
    fn a_granted_host_gives_a_client_and_withdrawing_it_takes_the_client_away() {
        // ★ This is the test the cache needs: a client built for a grant must not outlive the grant. If the cache were
        // keyed on the plugin alone, the call after the withdrawal would hand back the client built for the first grant —
        // and a user who withdrew a host would keep reaching it.
        let host = host_with(&[("network:fetch:api.github.com", true)]);
        assert!(fetcher_for(&host, &id("@acme/notes")).is_ok(), "granted");
        assert!(fetcher_for(&host, &id("@acme/notes")).is_ok(), "and again");

        host.db
            .lock()
            .record_grants("@acme/notes", &[("network:fetch:api.github.com".to_owned(), false)], 2, "d2")
            .expect("the decision is recorded");
        let refused = fetcher_for(&host, &id("@acme/notes")).expect_err("withdrawn");

        assert_eq!(refused.code, synra_plugin_host::host_calls::CallError::CAPABILITY_DENIED, "{refused}");
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
            host.secret_get(&plugin, "k").map(|_| ()),
            host.transfer_status(&plugin, "t").map(|_| ()),
            host.action_list(&plugin).map(|_| ()),
        ] {
            let error = refusal.expect_err("this build does not implement it");
            // ★ Read from the contract rather than spelled here. This assertion used to compare against the literal
            // `"NOT_IMPLEMENTED"`, which this host had invented — upper case with an underscore, when every code the
            // contract defines is camelCase. A test that asserts the implementation's own spelling cannot catch the
            // implementation spelling it wrong.
            assert_eq!(error.code, synra_plugin_host::host_calls::CallError::NOT_IMPLEMENTED, "{error:?}");
        }

        // ★ Storage is **not** in that list any more, and its absence is the point: it was the largest group in it, and a
        // plugin could not persist a byte. Asserted positively here, so that removing it from the loop cannot be mistaken
        // for removing the feature.
        assert_eq!(host.storage_get(&plugin, "k").expect("reads"), None, "an empty store reads as absent");
        host.storage_set(&plugin, "k", "v").expect("writes");
        assert_eq!(host.storage_get(&plugin, "k").expect("reads").as_deref(), Some("v"));
        assert_eq!(host.storage_used(&plugin).expect("measures"), 1);
        assert_eq!(host.storage_keys(&plugin, None).expect("lists"), vec!["k".to_owned()]);
        host.storage_delete(&plugin, "k").expect("removes");
        assert_eq!(host.storage_used(&plugin).expect("measures"), 0);

        // ★ And network is not in that list either. Asserted positively the same way: the refusal below is a **capability**
        // answer rather than a "this build cannot" one, which is the difference this test exists to protect — and it is
        // reachable without a network, because the guard refuses before anything is sent.
        let refused = host.fetch(&plugin, r#"{"url":"https://api.github.com/"}"#).expect_err("no grant");
        assert_eq!(refused.code, synra_plugin_host::host_calls::CallError::CAPABILITY_DENIED, "{refused:?}");
    }

#[test]
fn a_bad_address_is_the_plugins_mistake_rather_than_a_missing_feature() {
    // ★ The ordering, which is the whole reason this host delegates to `HeadlessPlatform`.
    //
    // This host answered every platform call with `notImplemented` — including one whose URL was garbage. A plugin that
    // supplied `javascript:` was then told the *installation* lacked a browser, which is a fact about the machine rather
    // than about its own argument, and its author had nothing to act on.
    //
    // `HeadlessPlatform` runs the guard and *then* refuses, so a caller learns about the first thing it can fix.
    let host = host_with(&[]);
    let plugin = id("@acme/notes");

    // The plugin's mistake: `badArgument`, because the address is the thing that is wrong.
    let refused = host
        .platform(&plugin, "open-url", "javascript:alert(1)")
        .expect_err("the guard refuses this scheme");
    assert_eq!(refused.code, "badArgument", "{refused:?}");
    assert!(refused.message.contains("javascript"), "{}", refused.message);

    // The installation's limitation: `notImplemented`, for an address that is perfectly fine.
    let refused = host
        .platform(&plugin, "open-url", "https://example.com")
        .expect_err("a headless host has no browser");
    assert_eq!(refused.code, "notImplemented", "{refused:?}");

    // And a name that is not a platform action is the caller's mistake rather than either of those.
    let refused = host
        .platform(&plugin, "not-an-action", "")
        .expect_err("that is not an action");
    assert_eq!(refused.code, "badArgument", "{refused:?}");
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
