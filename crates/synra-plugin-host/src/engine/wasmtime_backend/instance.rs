use std::time::Duration;

use wasmtime::component::Instance;
use wasmtime::{Store, StoreLimitsBuilder};

use crate::engine::executor::ticks_for;
use crate::engine::types::{BackendError, BackendKind, CallBudget, CallOutcome, PluginInstance, Work};

use super::StoreData;
use super::config::NO_DEADLINE_TICKS;

/// One instantiated plugin.
pub(super) struct EngineInstance {
    pub(super) store: Store<StoreData>,
    pub(super) instance: Instance,
    kind: BackendKind,
    deadline_epoch: Option<u64>,
    /// How much the plugin's memories have been told they may reach, so `memory_bytes` answers with the number the
    /// ceiling was enforced against rather than with a guess.
    ceiling: u64,
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
        // What the limiter has been told about, which is the number the budget was enforced against. A value read from
        // the guest's own memory would be the thing being measured rather than the measurement.
        u64::try_from(self.store.data().ceiling)
            .unwrap_or(u64::MAX)
            .min(self.ceiling)
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
        // ── Layer 1: the instruction budget ──
        if let Some(fuel) = budget.fuel {
            self.store
                .set_fuel(fuel)
                .map_err(|error| BackendError::Engine {
                    detail: format!("the fuel budget could not be set: {error}"),
                })?;
        } else {
            // ★ And "no instruction limit" has to be **given** fuel rather than left alone, which is the one thing this
            // layer cannot express by doing nothing.
            //
            // With `consume_fuel(true)`, a call that named no amount previously inherited
            // either nothing — a fresh instance, which traps at once with `FuelExhausted { fuel: 0 }` — or the previous
            // call's remainder on a reused one, and a remainder can be zero. Both are a plugin reported as out of
            // instructions when its budget named no instruction limit.
            //
            // `u64::MAX` is what wasmtime documents for effectively-unlimited fuel, and it is safe here where the same value
            // was **not** safe for the epoch deadline: fuel is subtracted as instructions run, not added to a counter.
            self.store
                .set_fuel(u64::MAX)
                .map_err(|error| BackendError::Engine {
                    detail: format!("the fuel budget could not be set: {error}"),
                })?;
        }

        // ── Layer 2: the wall clock ──
        //
        // The deadline is in *ticks beyond now*, and the counter is advanced by the executor's ticker. An engine whose
        // executor has stopped ticking therefore reaches no deadline at all — which is why a host asks
        // `WasmExecutor::enforces_timeouts` before it relies on this, rather than trusting the number set here.
        if let Some(timeout) = budget.timeout {
            let ticks = ticks_for(timeout);
            self.store.set_epoch_deadline(ticks);
            self.deadline_epoch = Some(ticks);
        } else {
            // Each call replaces the constructor's finite deadline or the previous call's limit.
            // Leave room for the current epoch when Wasmtime adds this relative deadline.
            self.store.set_epoch_deadline(NO_DEADLINE_TICKS);
            self.deadline_epoch = None;
        }

        // ── Layer 3: memory ──
        if let Some(ceiling) = budget.max_memory_growth {
            let wanted = usize::try_from(ceiling).unwrap_or(usize::MAX);
            self.store.data_mut().ceiling = wanted;
            self.store.data_mut().limits = StoreLimitsBuilder::new().memory_size(wanted).build();
            self.ceiling = ceiling;
        }
        self.store.data_mut().memory_refused = false;

        // ★ The purity rule, set per call. See `StoreData::side_effects`.
        self.store.data_mut().side_effects = work.allows_side_effects();

        // ★ The fuel is read as a pair around the call: the store is *set* to the budget above (or `u64::MAX` for "no
        // limit"), and what the guest spent is what is missing afterwards. Read into a local before the match so a call
        // that never starts still leaves `last_fuel` describing the previous one rather than a fabricated zero.
        let granted = self.store.get_fuel().ok();
        let outcome = match self.dispatch(work) {
            Ok(outcome) => Ok(outcome),
            Err(failure) => Ok(failure.into_outcome(
                budget,
                self.store.data().memory_refused,
                // ★ The **limiter's** ceiling, not `memory_bytes()`.
                //
                // They answer different questions and differ exactly when the budget names no ceiling: `memory_bytes` reports
                // what the budget asked for — zero before any call names one — while the limiter enforces the store's own
                // value, which starts at `INSTANTIATION_CEILING`. Reporting the first made a `MemoryExceeded` outcome say the
                // limit was zero when the wall the guest hit was sixteen mebibytes, which is the number a plugin author would
                // go and change.
                u64::try_from(self.store.data().ceiling).unwrap_or(u64::MAX),
            )),
        };
        if let (Some(granted), Ok(remaining)) = (granted, self.store.get_fuel()) {
            self.last_fuel = Some(granted.saturating_sub(remaining));
        }
        outcome
    }
}

impl EngineInstance {
    pub(super) const fn new(store: Store<StoreData>, instance: Instance, kind: BackendKind) -> Self {
        Self {
            store,
            instance,
            kind,
            deadline_epoch: None,
            // No call budget has set a ceiling yet. The store still enforces its instantiation limit.
            ceiling: 0,
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
    fn into_outcome(
        self,
        budget: CallBudget,
        memory_refused: bool,
        effective_ceiling: u64,
    ) -> CallOutcome {
        match self {
            Self::MissingExport {
                interface,
                function,
            } => CallOutcome::Trap {
                detail: format!("the component does not export {interface}.{function}"),
            },
            Self::Trap(error) => classify(&error, budget, memory_refused, effective_ceiling),
        }
    }
}

/// Turns an engine error into the outcome the caller handles.
///
/// `effective_ceiling` is the ceiling **in force**, not the one the budget named, and the distinction is the point: the
/// instantiation ceiling of sixteen mebibytes applies to a budget that named nothing, and reporting
/// `budget.max_memory_growth.unwrap_or(0)` told a plugin author their limit was **zero** when it was sixteen mebibytes. A
/// number that describes the wrong thing is worse than no number, because it is the number they will go and change.
///
/// # Why this is a function and not a `match` at the call site
///
/// Because the three limits produce three *different* errors, and each has a different thing a user can do: raise the
/// instruction budget, raise the time limit, or give the plugin more memory. Collapsing them into "the plugin failed"
/// would put the work of telling them apart on whoever reads the message.
fn classify(
    error: &wasmtime::Error,
    budget: CallBudget,
    memory_refused: bool,
    effective_ceiling: u64,
) -> CallOutcome {
    if memory_refused {
        return CallOutcome::MemoryExceeded {
            limit: effective_ceiling,
        };
    }
    let text = format!("{error:#}");
    let lowered = text.to_lowercase();
    if lowered.contains("epoch") || lowered.contains("interrupt") {
        return CallOutcome::Timeout {
            after: budget.timeout.unwrap_or(Duration::ZERO),
        };
    }
    if lowered.contains("fuel") {
        return CallOutcome::FuelExhausted {
            fuel: budget.fuel.unwrap_or(0),
        };
    }
    CallOutcome::Trap { detail: text }
}
