//! What a host call is authorised against.
//!
//! # Why this is not in `linker`
//!
//! Because it was, and it did not belong there: the linker is the Wasm-specific glue that defines host functions on a
//! `wasmtime::Linker`, and `LinkerSession` is a plain struct — an identifier, a capability set, a rate budget, an audit
//! buffer and a host. Nothing in it needs wasmtime.
//!
//! That distinction became load-bearing: `linker` is behind the `wasm-runtime` feature, so `LinkerSession` was behind it
//! too, and `PluginInstance::set_session` could not name its own parameter in a build with no engine. A type that
//! describes *what a call is allowed to do* should not be compiled out along with the engine that happens to execute it.
//!
//! # Why the session is created per call rather than stored on the plugin
//!
//! Because the grants and the budget belong to the plugin but the *host* may differ between hosts of the same kernel —
//! and because a session is the unit the audit is attributed to. Making it an argument keeps "who is asking, under what
//! grant, against which budget" a statement the caller makes rather than state that can go stale.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_capability::CapabilitySet;
use synra_observe::audit::AuditEntry;
use synra_protocol::ids::PluginId;

use crate::host_calls::Host;
use crate::quota::Budget;

/// What a plugin may do, while it is doing it.
///
/// # Why the host is an `Arc` here and a borrow in [`HostCalls`](crate::host_calls::HostCalls)
///
/// Because a `Store` owns its data and may be moved between threads, so a reference into a caller's frame is a reference
/// it cannot carry. The kernel hands out an `Arc<dyn Host>` and the store holds a clone of it, which is the same sharing
/// an `Arc<Kernel>` already is; the borrow is taken per call, for as long as the check runs.
pub struct LinkerSession {
    /// The plugin these calls are made on behalf of.
    pub plugin: PluginId,
    /// What it holds.
    pub grants: CapabilitySet,
    /// The budget its calls are counted against.
    pub budget: Arc<Budget>,
    /// What it did, in the order it did it.
    ///
    /// ★ Still a buffer of its own, and that is deliberate rather than finished. For the audit trail to be worth
    /// anything these entries have to outlive the instance that made them — they belong in the kernel's ring, which
    /// outlives the plugin. That is a shared handle rather than a `Vec`, and it is **not done**: nothing constructs a
    /// session in production yet (see `PluginInstance::set_session`), so the shape that sharing should take is a
    /// question for the step that has a caller for it rather than a guess made here.
    pub audit: Mutex<Vec<AuditEntry>>,
    /// The host the effects reach.
    pub host: Arc<dyn Host>,
}

impl LinkerSession {
    /// A session for a plugin.
    #[must_use]
    pub fn new(plugin: PluginId, grants: CapabilitySet, budget: Arc<Budget>, host: Arc<dyn Host>) -> Self {
        Self { plugin, grants, budget, audit: Mutex::new(Vec::new()), host }
    }

    /// What the plugin did, in the order it did it.
    #[must_use]
    pub fn recorded(&self) -> Vec<AuditEntry> {
        self.audit.lock().clone()
    }
}

impl std::fmt::Debug for LinkerSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinkerSession")
            .field("plugin", &self.plugin)
            .field("grants", &self.grants.len())
            .field("audited", &self.audit.lock().len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
