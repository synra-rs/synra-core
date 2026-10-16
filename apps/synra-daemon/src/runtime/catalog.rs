//! Answering a catalogue search.
//!
//! # Why this is a module rather than a method body
//!
//! Because it is the one place in this host that talks to a machine nobody configured: `RegistryConfig`'s default is the
//! public registry, and the answer depends on whether a network exists. That is three facts to get right — which mirrors,
//! what is cached, and what a caller is told when neither works — and they read better here than inside `commands.rs`
//! between two database calls.
//!
//! # What a caller learns
//!
//! The design's offline row is *"registry unreachable → use the cached packument (7-day TTL); show offline mode"*, so the
//! answer carries **where it came from** rather than only what it holds. A screen that could not tell a live answer from a
//! seven-day-old one would be showing a catalogue it cannot vouch for — and `synra plugin search` on a train would look
//! exactly like one on a desk.

use synra_plugin_host::catalog::{CatalogCache, CatalogClient, CatalogError, Fetches, Origin};
use synra_protocol::error::ErrorCode;
use synra_control::Refusal;

use super::state::Runtime;

/// The registry's default configuration, and the cache under this device's data directory.
#[must_use]
pub fn cache_for(runtime: &Runtime) -> CatalogCache {
    // `Paths` is the one place that decides where things live, so the cache directory is asked for rather than joined here —
    // the same reasoning `serve.rs` follows for the log directory.
    let paths = synra_store::Paths::new(&runtime.data_dir, runtime.data_dir.join("cache"));
    CatalogCache::new(paths.catalog_cache_dir())
}

/// A fetcher over the real network client.
///
/// # Why this is a struct of its own rather than a method on the client
///
/// Because `synra_fetch::Client` is a concrete type in another crate and the catalogue client wants a trait: the interesting
/// behaviour is what happens when a fetch **fails**, which cannot be arranged through a type whose failures need a network.
/// This is the three-line adapter that connects them.
struct RegistryFetcher {
    client: synra_fetch::Client,
}

impl Fetches for RegistryFetcher {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let request = synra_fetch::Request {
            // The registry is read, not written to.
            method: "GET".to_owned(),
            url: url.to_owned(),
            headers: std::collections::BTreeMap::new(),
            body: None,
        };
        self.client
            .fetch(&request)
            // The body is text, and the catalogue's own parser is what decides whether it is a packument — the client
            // deliberately does not parse, so a registry that answers with an error page arrives as text and is rejected by
            // the parser with a reason rather than by this adapter with none.
            .map(|response| response.body.into_bytes())
            .map_err(|refusal| refusal.to_string())
    }
}

/// Searches the catalogue for one package.
///
/// # Errors
///
/// [`Refusal`] with [`ErrorCode::DeviceOffline`] when no mirror answered and nothing was cached — the code the design's
/// offline row implies, and a different answer from "no such package", which is what an empty list would say.
pub fn search(runtime: &Runtime, package: &str) -> Result<serde_json::Value, Refusal> {
    let config = synra_plugin_host::registry::RegistryConfig::new();
    // The guard is built for the hosts this configuration resolves to, so a registry is reachable **because it is a
    // registry** rather than because the guard happens to allow everything.
    let hosts: Vec<String> = config.resolve(package).into_iter().filter_map(|url| host_of(&url)).collect();
    let fetcher = RegistryFetcher {
        client: synra_fetch::Client::new(
            synra_core::network::NetworkGuard::for_hosts(&hosts),
            synra_fetch::Limits::default(),
        ),
    };
    let client = CatalogClient::new(config, cache_for(runtime), fetcher);

    let now_ms = i64::try_from(crate::runtime::now_ms()).unwrap_or(i64::MAX);
    match client.packument(package, now_ms) {
        Ok(fetched) => Ok(describe(&fetched.packument, &fetched.origin)),
        Err(CatalogError::Unreachable { attempts, .. }) => Err(Refusal::new(
            ErrorCode::DeviceOffline,
            format!(
                "no registry answered for `{package}` and nothing is cached: {}",
                attempts
                    .iter()
                    .map(|(mirror, why)| format!("{mirror}: {why}"))
                    .collect::<Vec<String>>()
                    .join("; ")
            ),
        )),
        Err(error) => Err(Refusal::new(ErrorCode::Unsupported, error.to_string())),
    }
}

/// A packument as the interface reads it.
///
/// # Why the origin is a field rather than a separate answer
///
/// Because the two are read together: "1.2.3 is the latest" means one thing from a registry that just answered and another
/// from a cache that is eight days old, and a caller that had to make two requests to learn both would be able to show one
/// without the other.
fn describe(packument: &synra_plugin_host::registry::Packument, origin: &Origin) -> serde_json::Value {
    let latest = packument.tagged("latest");
    let versions: Vec<&str> = packument.versions.names().collect();

    let origin = match origin {
        Origin::Registry { mirror } => serde_json::json!({ "source": "registry", "mirror": mirror }),
        Origin::Cache { age_ms, stale } => {
            serde_json::json!({ "source": "cache", "ageMs": age_ms, "stale": stale })
        }
        // ★ Reported rather than guessed, and this arm exists because `Origin` is `#[non_exhaustive]` — which is the
        // attribute doing its job: the enum can grow a third place a catalogue comes from without breaking this caller, and
        // what it costs is this line. Saying "unknown" is the honest answer for a variant this build has never heard of;
        // picking one of the two above would tell a user their catalogue came from somewhere it did not.
        _ => serde_json::json!({ "source": "unknown" }),
    };

    serde_json::json!({
        "package": packument.name,
        "latest": latest.map(|entry| entry.version.clone()),
        "versions": versions,
        "origin": origin,
    })
}

/// The host of a URL, for the guard.
///
/// A URL this cannot read yields no host, and a mirror that yields no host is simply not in the guard's list — which makes it
/// unreachable rather than allowed, because the guard is an allow-list and an unparsed entry must not become a wildcard.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, rest)| rest)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_owned())
}

#[cfg(test)]
mod tests;
