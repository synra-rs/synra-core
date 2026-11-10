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
//! | storage and network | local storage and scoped fetch | stored values and grants |
//! | platform | validates requests before refusing effects | the headless platform guard |
//! | other calls | structured refusals | this host cannot perform those effects |
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
use synra_protocol::ids::PluginId;

mod calls;
mod network;

#[cfg(test)]
mod event_tests;
#[cfg(test)]
mod tests;

/// One plugin's fetcher, and the hosts it was built for.
///
/// ★ A name rather than the type written out at the field: the tuple means "this client, for exactly these hosts", and
/// spelling it inline made the field the most complicated thing in the struct. The alias lets the field's doc say *why* the
/// host list is stored beside the client instead of a reader having to reconstruct it from a nested generic.
type FetchClients = Mutex<std::collections::HashMap<PluginId, (Vec<String>, Arc<synra_fetch::Client>)>>;

/// The daemon's answer to a plugin's host calls.
pub(crate) struct KernelHost {
    events: Arc<synra_core::plugin_events::EventService>,
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
    pub(crate) fn events(&self) -> Arc<synra_core::plugin_events::EventService> {
        Arc::clone(&self.events)
    }
    /// A host over the daemon's own state.
    #[must_use]
    pub(crate) fn new(db: Arc<Mutex<synra_store::SynraDb>>, version: impl Into<String>) -> Self {
        let events = synra_core::plugin_events::EventService::new(Arc::clone(&db));
        Self {
            events,
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
