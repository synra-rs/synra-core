//! Cached fetch clients and grant-derived host scope.

use std::sync::Arc;

use synra_plugin_host::host_calls::CallError;
use synra_protocol::ids::PluginId;

use super::KernelHost;

/// The fetcher for one plugin, built or rebuilt from what the user has granted it.
///
/// # Errors
///
/// [`CallError`] with `capabilityDenied` when the plugin holds no `network:fetch:<host>` grant at all — which is a
/// different answer from "that host is not one of them", and the one a plugin author needs when nothing works.
pub(super) fn fetcher_for(host: &KernelHost, plugin: &PluginId) -> Result<Arc<synra_fetch::Client>, CallError> {
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
pub(super) fn host_of(capability: &str) -> Option<String> {
    let rest = capability.strip_prefix("network:fetch:")?;
    let host = rest.split(':').next().unwrap_or_default();
    if host.is_empty() || host == "*" {
        return None;
    }
    Some(host.to_owned())
}
