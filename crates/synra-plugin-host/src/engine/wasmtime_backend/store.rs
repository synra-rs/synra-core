//! Per-instance authorization, accounting and enforced resource limits.

use super::config::INSTANTIATION_CEILING;
use wasmtime::{StoreLimits, StoreLimitsBuilder};

/// What an instance's store holds.
pub(crate) struct StoreData {
    /// The ceiling a growth is measured against, kept here because the engine's limiter does not report it back.
    pub(super) ceiling: usize,
    /// Set when a growth the budget refused was attempted, so a call can report *why* it trapped rather than a
    /// generic trap the plugin author cannot act on.
    pub(super) memory_refused: bool,
    pub(super) limits: StoreLimits,
    /// The plugin whose calls this instance makes, when the host gave it one.
    ///
    /// `None` for an instance the host built without a session, which is the only way a host function can be reached
    /// without a gate — and the answer there is a refusal rather than a call.
    pub(crate) session: Option<Box<dyn std::any::Any + Send + Sync>>,
    /// Actual imported host function attempts, including refused calls.
    pub(crate) host_calls: u64,
    /// Whether the call now running is allowed to have side effects.
    ///
    /// ★ Why the *call* decides this rather than the plugin or its grants.
    ///
    /// `share.can-handle` runs for **every** plugin the router asks, before a user has chosen anything, and the contract
    /// says it is a pure function. A plugin that wrote a file, opened a browser or sent a message there would have done it
    /// for every share the user then cancelled.
    ///
    /// `Work::allows_side_effects` already answers the question — `false` for `CanHandle`, `true` for everything else —
    /// and **nothing called it**. Its doc says "the host is what makes that true, by running it with a context whose
    /// action-shaped calls are refused", and no such context existed: a plugin's `can-handle` could call `device-send`,
    /// `platform-open-url`, `secret-set` or anything else its grants allowed, during the matching pass.
    ///
    /// Set before every call rather than at instantiation, because the same instance is asked `can-handle` first and
    /// `execute` afterwards: the answer belongs to the call, not to the store.
    pub(crate) side_effects: bool,
}

impl StoreData {
    /// Creates bounded instance state without a host authorization session.
    pub(in crate::engine) fn new() -> Self {
        Self {
            ceiling: INSTANTIATION_CEILING,
            memory_refused: false,
            limits: StoreLimitsBuilder::new()
                .memory_size(INSTANTIATION_CEILING)
                .build(),
            session: None,
            host_calls: 0,
            side_effects: true,
        }
    }
}

impl wasmtime::ResourceLimiter for StoreData {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // The engine's own limiter does the accounting; what this adds is remembering *that* it refused, because the
        // trap that follows says only that a memory could not grow.
        let permitted = self.limits.memory_growing(current, desired, maximum)?;
        if !permitted {
            self.memory_refused = true;
        }
        Ok(permitted)
    }

    fn memory_grow_failed(&mut self, error: anyhow::Error) -> anyhow::Result<()> {
        self.memory_refused = true;
        self.limits.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }

    fn instances(&self) -> usize {
        self.limits.instances()
    }

    fn tables(&self) -> usize {
        self.limits.tables()
    }

    fn memories(&self) -> usize {
        self.limits.memories()
    }
}
