//! Building the engine this daemon runs plugins on.
//!
//! # Where the rest lives
//!
//! In [`synra_core::plugin`]: which installed plugins should run and why (`load_installed` / `load_plugin`), and which
//! directories on disk the database has not seen (`record_discovered_plugins`). Both used to live here, and the desktop
//! shell — which has the same facts to assemble — never had a copy of either, so a plugin installed from the window was
//! listed, could be enabled, and was never loaded. What stays here is the daemon's own half: the engine it brings, its
//! audit sink and the recorder the gate counts into.
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

use synra_plugin_host::BackendError;

use synra_core::dispatch::PluginSet;

pub use synra_core::plugin::{
    Discovered, LoadedSummary, Refused, load_installed, record_discovered_plugins,
};

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
pub fn build_set(
    db: &std::sync::Arc<parking_lot::Mutex<synra_store::SynraDb>>,
    metrics: &std::sync::Arc<synra_observe::metrics::RingRecorder>,
) -> Result<PluginSet, BackendError> {
    let kind = synra_plugin_host::BackendKind::default_for(synra_plugin_host::HostKind::Headless);
    let backend = synra_plugin_host::Backend::new(std::sync::Arc::new(
        synra_plugin_host::engine::WasmtimeBackend::new(kind)?,
    ));
    // ★ The engine is asked whether it can enforce what this host will ask of it, **before** any plugin is loaded.
    //
    // `first_gap` is this layer's safety argument — *"the caller refuses rather than running third-party code with a bound it
    // does not have"* — and this is the caller. Asked here rather than per call for the reason the error variant records: a
    // missing limit is a fact about the installation, and this is the only moment somebody can act on it.
    synra_plugin_host::engine::check_enforceable(
        &backend,
        &synra_plugin_host::quota::Quota::default(),
    )?;
    // ★ The host is what makes the capability gate run. Without one there is no session, and `linker::run` refuses
    // every host call — so the gate never ran and nothing was audited.
    let host = std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
        std::sync::Arc::clone(db),
        env!("CARGO_PKG_VERSION"),
    ));

    // ★ And the audit gets its durable half, which it has never had.
    //
    // `plugin_audit` was created by the first migration and its own comment says what it is for: *"A ring in memory, but the
    // durable part is what makes the interface's 'recent activity' survive a restart."* The ring was written — every call is
    // drained into it — and nothing ever wrote the table, so the audit a user sees is the last ten thousand calls of **this
    // run** and a restart empties it.
    //
    // The sink is a closure rather than a store handle on the set, because the kernel is what decides a call is auditable
    // and the host is what has a database. A write that fails is logged and does not fail the call: the call has already
    // happened, and refusing it afterwards would tell a plugin its action did not occur when it did — the same reasoning as
    // `checkpoint_intent`.
    let audit_db = std::sync::Arc::clone(db);
    let sink = std::sync::Arc::new(move |entry: &synra_observe::audit::AuditEntry| {
        let record = synra_store::records::AuditRecord {
            plugin_id: entry.plugin.as_str().to_owned(),
            capability: entry.capability.to_string(),
            outcome: entry.outcome.as_str().to_owned(),
            at_ms: entry.at_ms,
            elapsed_ms: entry.elapsed_ms.map(|elapsed| i64::try_from(elapsed).unwrap_or(i64::MAX)),
            // ★ The action's trace, when the call had one. `can-handle` and lifecycle calls do not, and `None` says that
            // rather than making every audit row look like part of a user action.
            trace_id: entry.trace.map(|trace| trace.to_string()),
        };
        if let Err(error) = audit_db.lock().record_audit(&record) {
            tracing::error!(
                plugin = entry.plugin.as_str(),
                "an audit record could not be written down: {error}. The call it describes has already happened."
            );
        }
    });

    // ★ And the gate's counters get somewhere to go.
    //
    // The recorder is created by the daemon and handed in rather than made here, because the daemon is what can *read* it —
    // a recorder built inside this function and dropped on return would be a metrics subsystem nobody can see, which is
    // exactly what these metrics were before there was a producer at all.
    Ok(PluginSet::new(backend, host)
        .with_audit_sink(sink)
        .with_metrics(std::sync::Arc::clone(metrics)))
}
