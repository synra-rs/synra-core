//! Per-instance authorization, accounting and enforced resource limits.

use std::time::Duration;

use super::config::INSTANTIATION_CEILING;
use crate::engine::CallBudget;
use wasmtime::StoreLimits;

#[derive(Clone, Copy)]
pub(super) struct EffectiveBudget {
    pub(super) fuel: Option<u64>,
    pub(super) timeout: Option<Duration>,
    pub(super) memory_ceiling: usize,
}

impl From<CallBudget> for EffectiveBudget {
    fn from(budget: CallBudget) -> Self {
        Self {
            fuel: budget.fuel,
            timeout: budget.timeout,
            memory_ceiling: budget
                .max_memory_growth
                .map_or(INSTANTIATION_CEILING, |bytes| {
                    usize::try_from(bytes).unwrap_or(usize::MAX)
                }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("requested linear memory of {desired} bytes exceeds the host ceiling of {limit} bytes")]
pub(super) struct MemoryCeilingExceeded {
    pub(super) limit: usize,
    desired: usize,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum GrowthRefusal {
    #[error("requested {desired} bytes with a linear memory maximum of {maximum} bytes")]
    Maximum { desired: usize, maximum: usize },
    #[error("the engine could not allocate the requested linear memory: {0:#}")]
    Allocation(anyhow::Error),
}

/// What an instance's store holds.
pub(crate) struct StoreData {
    memory_ceiling: usize,
    /// Latest recoverable growth failure, for diagnostics on an independent trap in the same call.
    pub(super) growth_refusal: Option<GrowthRefusal>,
    limits: StoreLimits,
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
            memory_ceiling: INSTANTIATION_CEILING,
            growth_refusal: None,
            limits: StoreLimits::default(),
            session: None,
            host_calls: 0,
            side_effects: true,
        }
    }

    pub(super) fn begin_call(&mut self, budget: EffectiveBudget, side_effects: bool) {
        self.memory_ceiling = budget.memory_ceiling;
        self.growth_refusal = None;
        self.side_effects = side_effects;
    }
}

impl wasmtime::ResourceLimiter for StoreData {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // A stricter module or allocator maximum keeps Wasm's recoverable `memory.grow` failure.
        if let Some(maximum) = maximum
            && maximum <= self.memory_ceiling
            && desired > maximum
        {
            self.growth_refusal = Some(GrowthRefusal::Maximum { desired, maximum });
            return Ok(false);
        }
        // Trap at the host policy boundary so the error chain identifies the actual cause.
        if desired > self.memory_ceiling {
            return Err(MemoryCeilingExceeded {
                limit: self.memory_ceiling,
                desired,
            }
            .into());
        }
        Ok(true)
    }

    fn memory_grow_failed(&mut self, error: anyhow::Error) -> anyhow::Result<()> {
        self.growth_refusal = Some(GrowthRefusal::Allocation(error));
        Ok(())
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
