use wasmtime::Store;
use wasmtime::component::Instance;

use crate::engine::executor::ticks_for;
use crate::engine::types::{
    BackendError, BackendKind, CallBudget, CallOutcome, PluginInstance, Work,
};

use super::StoreData;
use super::config::NO_DEADLINE_TICKS;
use super::failure;
use super::store::EffectiveBudget;

/// One instantiated plugin.
pub(super) struct EngineInstance {
    pub(super) store: Store<StoreData>,
    pub(super) instance: Instance,
    kind: BackendKind,
    deadline_epoch: Option<u64>,
    /// The effective ceiling of the most recent call, or zero before the first call.
    last_memory_ceiling: u64,
    /// Fuel the most recent call consumed, read back from the store after it ended.
    last_fuel: Option<u64>,
}

impl std::fmt::Debug for EngineInstance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineInstance")
            .field("kind", &self.kind)
            .field("host_calls", &self.store.data().host_calls)
            .field("deadline_epoch", &self.deadline_epoch)
            .finish_non_exhaustive()
    }
}

impl PluginInstance for EngineInstance {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    /// Installs the session the linker checks every host call against.
    ///
    /// # ★ What this changes in production
    ///
    /// Everything. `instantiate` leaves `session: None`, and `linker::run` refuses **every** host call when there is no
    /// session — so before this method was called by anyone, the capability gate never ran: no plugin could reach a host
    /// function at all, and nothing was audited. The gate is the mechanism the whole capability model rests on, and it
    /// was inert.
    ///
    /// The session goes into the store's own data, which is where the linker reads it from. `LinkerSession` holds
    /// `Arc`s, so moving it in is a pointer move.
    fn set_session(&mut self, session: crate::engine::session::LinkerSession) {
        self.store.data_mut().session = Some(Box::new(session));
    }

    fn memory_bytes(&self) -> u64 {
        self.last_memory_ceiling
    }

    fn host_calls(&self) -> u64 {
        self.store.data().host_calls
    }

    fn deadline_epoch(&self) -> Option<u64> {
        self.deadline_epoch
    }

    fn last_fuel_consumed(&self) -> Option<u64> {
        self.last_fuel
    }

    fn call(&mut self, work: &Work, budget: CallBudget) -> Result<CallOutcome, BackendError> {
        let budget = EffectiveBudget::from(budget);
        // Replace the constructor's fuel or the previous call's remainder.
        let granted = budget.fuel.unwrap_or(u64::MAX);
        self.store
            .set_fuel(granted)
            .map_err(|error| BackendError::Engine {
                detail: format!("the fuel budget could not be set: {error}"),
            })?;
        self.deadline_epoch = budget.timeout.map(ticks_for);
        self.store
            .set_epoch_deadline(self.deadline_epoch.unwrap_or(NO_DEADLINE_TICKS));
        self.store
            .data_mut()
            .begin_call(budget, work.allows_side_effects());
        self.last_memory_ceiling = u64::try_from(budget.memory_ceiling).unwrap_or(u64::MAX);

        let outcome = self
            .dispatch(work)
            .unwrap_or_else(|error| error.into_outcome(budget, self.store.data()));
        self.last_fuel = self
            .store
            .get_fuel()
            .ok()
            .map(|remaining| granted.saturating_sub(remaining));
        Ok(outcome)
    }
}

impl EngineInstance {
    pub(super) const fn new(
        store: Store<StoreData>,
        instance: Instance,
        kind: BackendKind,
    ) -> Self {
        Self {
            store,
            instance,
            kind,
            deadline_epoch: None,
            // No call budget has set a ceiling yet. The store still enforces its instantiation limit.
            last_memory_ceiling: 0,
            last_fuel: None,
        }
    }
}

/// Why a call could not be made at all.
pub(super) enum CallFailure {
    /// The component does not export that function.
    MissingExport {
        /// The interface.
        interface: &'static str,
        /// The function.
        function: &'static str,
    },
    /// The guest trapped.
    Trap(wasmtime::Error),
}

impl CallFailure {
    /// What the caller is told.
    fn into_outcome(self, budget: EffectiveBudget, store: &StoreData) -> CallOutcome {
        match self {
            Self::MissingExport {
                interface,
                function,
            } => CallOutcome::Trap {
                detail: format!("the component does not export {interface}.{function}"),
            },
            Self::Trap(error) => failure::classify(&error, budget, store.growth_refusal.as_ref()),
        }
    }
}
