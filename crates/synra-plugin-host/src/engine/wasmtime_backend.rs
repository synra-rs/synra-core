//! Wasmtime compilation, bounded instance startup and execution budgeting.
//!
//! Configuration, compiled artifacts, instance state and typed guest invocation have separate
//! owners. WIT-generated host bindings are installed by the shared linker.

use std::sync::Arc;
use std::time::Duration;

use wasmtime::component::{Component, Instance, Linker};

mod artifact;
pub(super) mod bindings;
mod config;
mod imports;
mod invoke;
mod store;
pub use artifact::EngineArtifact;
#[cfg(test)]
use config::INSTANTIATION_CEILING;
pub(crate) use config::engine_config;
use config::{INSTANTIATION_FUEL, INSTANTIATION_TIMEOUT, NO_DEADLINE_TICKS};
pub(crate) use store::StoreData;
use wasmtime::{Engine, Store, StoreLimitsBuilder};

use super::executor::{Epoch, EpochTicker};
use super::types::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, Enforcement,
    PluginInstance, WasmBackend, Work,
};

/// The crate's own version, which is the engine-version input to a compile cache key.
///
/// The engine's version is the crate's: `wasmtime` is pinned in `Cargo.toml`, so a change to it is a change to the
/// build rather than to a runtime value. A cache entry a rebuild cannot use is a miss, which is a recompilation and
/// not a crash.
pub(crate) const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One instantiated plugin.
pub(crate) struct EngineInstance {
    store: Store<StoreData>,
    instance: Instance,
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

/// How many ticks a timeout is worth.
///
/// The executor's period is ten milliseconds, and this is that arithmetic in one place: a timeout shorter than a tick
/// still gets one, because a deadline of "now" is a call that always fails.
fn ticks_for(timeout: Duration) -> u64 {
    let period = super::executor::EPOCH_PERIOD.as_nanos().max(1);
    let ticks = timeout.as_nanos().div_ceil(period);
    u64::try_from(ticks).unwrap_or(u64::MAX).max(1)
}

/// The name an interface is exported under.
///
/// # Why this is spelled out rather than assumed
///
/// A component's exports are keyed by their *interface-qualified* name — `synra:plugin/lifecycle@1.0.0`, with the
/// version on the interface rather than on the package — and the functions inside it are reached through that instance.
/// A lookup on the bare function name finds nothing, and the symptom is a call that reports "the component does not
/// export activate" for a component that plainly does: a plugin author's problem to have, and not one the host should
/// invent.
///
/// Both halves come from [`crate::host_surface`], which `build.rs` regenerates from the contract, so a version bump in
/// `wit/synra-plugin.wit` cannot leave this behind. The separator is `@` between the interface and its version and `/`
/// between the package and the interface, which is the component model's own grammar rather than a choice made here.
#[must_use]
pub(crate) fn interface_name(interface: &str) -> String {
    format!(
        "{}/{interface}@{}",
        crate::host_surface::PACKAGE,
        crate::host_surface::PACKAGE_VERSION,
    )
}

/// The fully flattened name of a function, for a component that exports its interface that way.
#[must_use]
pub(crate) fn export_name(interface: &str, function: &str) -> String {
    format!("{}#{function}", interface_name(interface))
}

/// Why a call could not be made at all.
enum CallFailure {
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

/// An engine, and the configuration it was built with.
#[derive(Clone)]
pub struct WasmtimeBackend {
    engine: Engine,
    kind: BackendKind,
    /// The epoch deadlines are measured against. Held so a caller can prove the engine it built is the one an
    /// executor's ticker advances, rather than a private counter nothing moves.
    epoch: Epoch,
    /// The ticker this backend started for itself, when it has no executor to share one with.
    ///
    /// `Some` after [`WasmtimeBackend::new`], `None` after [`WasmtimeBackend::with_epoch`] — in the second case the
    /// caller owns a ticker and this engine is one of its observers. Held rather than leaked because the ticker's thread
    /// ends when the value is dropped, so an engine that dropped it would be an engine whose deadlines stopped.
    ///
    /// Behind an `Arc` because this struct is `Clone` and a ticker owns a thread. A clone must advance the *same* epoch
    /// — two tickers over one epoch would double the rate, and a clone that started a second one would make the timeout
    /// it was cloned for arrive twice as fast as the budget asked.
    ticker: Option<Arc<EpochTicker>>,
}

impl std::fmt::Debug for WasmtimeBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmtimeBackend")
            .field("kind", &self.kind)
            .field("engine_version", &ENGINE_VERSION)
            .finish_non_exhaustive()
    }
}

impl WasmtimeBackend {
    /// Builds an engine with the security baseline the design document requires.
    ///
    /// # ★ This starts a ticker, and it did not before
    ///
    /// It used to be `Self::with_epoch(kind, Epoch::new())` — an epoch nothing advanced. That is precisely the failure
    /// the sibling constructor's doc comment calls impossible, committed by the constructor next to it: the wall-clock
    /// budget armed a deadline on a counter that would never reach it, so computing guests could run forever.
    /// Epoch interruption applies to running Wasm; synchronous host IO needs its own deadline and cancellation.
    ///
    /// An engine built this way has no executor to share an epoch with, so it brings its own ticker and holds it. The
    /// ticker stops when the backend is dropped, which is what the ownership is for.
    ///
    /// # Errors
    ///
    /// [`BackendError::Engine`] when the engine refuses the configuration, which is a build-time problem reported
    /// rather than panicked on.
    pub fn new(kind: BackendKind) -> Result<Self, BackendError> {
        let epoch = Epoch::new();
        let ticker = EpochTicker::start(epoch.clone());
        let mut backend = Self::with_epoch(kind, epoch)?;
        backend.ticker = Some(Arc::new(ticker));
        Ok(backend)
    }

    /// Builds an engine that shares an executor's epoch.
    ///
    /// # Why the epoch is passed rather than made here
    ///
    /// Because a deadline is only reached if something advances the counter. An engine with an epoch of its own would
    /// be an engine whose deadlines never fire — a wall-clock budget that silently does nothing, which is the failure
    /// this whole layer exists to make impossible.
    ///
    /// # ★ And why the epoch is now *observed* as well as held
    ///
    /// Because holding it was not enough. `Epoch::advance` moves that counter; the deadline is measured against
    /// wasmtime's own, which moves only when `Engine::increment_epoch` is called. Registering the engine here is what
    /// joins the two, so a ticker that advances the epoch cannot leave the engine behind.
    ///
    /// # Errors
    ///
    /// As [`WasmtimeBackend::new`].
    pub fn with_epoch(kind: BackendKind, epoch: Epoch) -> Result<Self, BackendError> {
        let engine = Engine::new(&engine_config(kind)).map_err(|error| BackendError::Engine {
            detail: format!("the engine refused its configuration: {error}"),
        })?;
        // ★ The join between the two counters, and the line whose absence made the wall-clock budget inert.
        //
        // `Epoch` is what the ticker advances; `Engine::increment_epoch` is what wasmtime measures a deadline against.
        // Registering here means an advance of one is an advance of the other, so no caller has to remember to do both
        // — which is exactly what no caller did.
        //
        // `Engine` is a handle to shared machinery, so the clone the closure keeps is the same engine, not a copy of it.
        {
            let engine = engine.clone();
            epoch.observe(move |_tick| engine.increment_epoch());
        }

        Ok(Self {
            engine,
            kind,
            epoch,
            ticker: None,
        })
    }

    /// The engine, for a caller that wants to build something else on it.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// The epoch this engine's deadlines are measured against.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    /// A sentence naming the engine, for a `doctor` report.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{} (engine version {ENGINE_VERSION})", self.kind)
    }
}

impl WasmBackend for WasmtimeBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn enforcement(&self) -> Enforcement {
        // ★ Not `Enforcement::full()`, which is what this returned and what it must not return.
        //
        // `full()` sets `precompile: true`. This backend does not implement `WasmBackend::precompile`, so it inherits
        // the trait default, which returns `BackendError::BackendUnavailable`. Nothing in the workspace overrides it —
        // `grep 'fn precompile'` finds the default and no implementor.
        //
        // So `full()` here was a claim about a capability that does not exist. `Enforcement` is what a caller reads to
        // decide whether a budget can be honoured, and a caller told "precompilation is available" would go on to ask
        // for it and get an error it had already been told could not happen. The three limits that *are* enforced are
        // real — fuel, epoch and memory are applied in `apply_budget` — so only the fourth is corrected here.
        //
        // ★ The test that covered this (`the_engine_reports_that_it_enforces_every_limit`) asserted that the constant
        // equals the constant. It could not have caught the difference, which is how the claim survived.
        Enforcement {
            precompile: false,
            ..Enforcement::full()
        }
    }

    fn engine_version(&self) -> &str {
        ENGINE_VERSION
    }

    fn compile(
        &self,
        wasm: &[u8],
        plugin_id: &str,
    ) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        if wasm.is_empty() {
            return Err(BackendError::Compile {
                detail: "the artifact is empty".to_owned(),
            });
        }
        // ★ Checked before the engine sees anything, and it is the only check here that can be made cheaply.
        //
        // A parse of a hostile artifact is the expensive part, and it is exactly what a size ceiling exists to avoid
        // paying. The message names both numbers, because "too large" leaves a plugin author guessing at the limit.
        if wasm.len() > super::MAX_COMPONENT_BYTES {
            return Err(BackendError::Compile {
                detail: format!(
                    "the artifact is {} bytes, and the largest this host compiles is {}",
                    wasm.len(),
                    super::MAX_COMPONENT_BYTES
                ),
            });
        }
        let component =
            Component::new(&self.engine, wasm).map_err(|error| BackendError::Compile {
                detail: format!("{error:#}"),
            })?;

        // ★ The import check happens here rather than at the first call. A component importing a function this host
        // does not provide is one built against a host that has it, and letting it link would move the failure to a
        // call site far from its cause. The names come from the component's own type, so what is checked is what the
        // artifact imports rather than what its manifest claims.
        let component_type = component.component_type();
        let imports = imports::calls(&component_type, &self.engine);

        // ★ The *exports* are checked here too, and for the same reason the imports are: a component that does not
        // export the three interfaces the contract requires is one built against a different contract, and a user
        // should be told that when the plugin is loaded rather than when they first share something with it.
        let mut exports = Vec::new();
        for (name, _) in component_type.exports(&self.engine) {
            exports.push(name.to_string());
        }
        exports.sort();
        // This low-level engine check also supports focused ABI and budget probes.
        // Package admission is stricter: component::inspect, called by the verifier and
        // executing PluginSet loads, requires the complete lifecycle, share and actions world.
        let required = crate::host_surface::EXPORTED_INTERFACES
            .first()
            .copied()
            .unwrap_or("lifecycle");
        let wanted = interface_name(required);
        // Either spelling a toolchain may produce: the interface as a nested instance, or flattened into names that
        // begin with it. A host that accepted only one would refuse components a real build emits.
        let found = exports
            .iter()
            .any(|name| *name == wanted || name.starts_with(&format!("{wanted}#")));
        if !found {
            return Err(BackendError::MissingExport { export: required });
        }

        let digest = super::scripted::digest_of(plugin_id, wasm);
        Ok(Box::new(EngineArtifact {
            component,
            digest,
            kind: self.kind,
            imports,
            exports,
        }))
    }

    fn instantiate(
        &self,
        backend: &Backend,
        compiled: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError> {
        // The artefact is reached through the trait object, and the type check is what keeps an artifact from another
        // engine from being handed to this one — which would decode as instructions rather than fail. `CompiledArtifact`
        // carries `Any` for exactly this: a backend has to be able to recognise its own artefact, and the alternative
        // is a downcast written once per backend with no type check at all.
        let Some(artifact) = (compiled as &dyn std::any::Any).downcast_ref::<EngineArtifact>()
        else {
            return Err(BackendError::Engine {
                detail: format!(
                    "a {} artefact cannot be run by the {} backend",
                    compiled.kind(),
                    self.kind
                ),
            });
        };
        let _ = backend;

        let mut store = Store::new(&self.engine, StoreData::new());
        store.limiter(|data| data as &mut dyn wasmtime::ResourceLimiter);
        store
            .set_fuel(INSTANTIATION_FUEL)
            .map_err(|error| BackendError::Engine {
                detail: format!("the instantiation fuel budget could not be set: {error}"),
            })?;
        // Startup has its own finite budget; normal calls replace it with their configured limits.
        store.set_epoch_deadline(ticks_for(INSTANTIATION_TIMEOUT));
        store.epoch_deadline_trap();

        let mut linker: Linker<StoreData> = Linker::new(&self.engine);
        crate::engine::linker::define(&mut linker).map_err(|error| BackendError::Engine {
            detail: format!("the host functions could not be defined: {error:#}"),
        })?;

        let instance = linker
            .instantiate(&mut store, &artifact.component)
            .map_err(|error| BackendError::Instantiate {
                detail: format!("{error:#}"),
            })?;

        Ok(Box::new(EngineInstance {
            store,
            instance,
            kind: self.kind,
            deadline_epoch: None,
            // Zero, and that is what `memory_bytes` means here: the ceiling the **budget** has named, which is none until a
            // call names one. The wall the limiter actually enforces is the store's own `ceiling`, which starts at
            // `INSTANTIATION_CEILING` — a different number answering a different question, and the one `classify` needs.
            ceiling: 0,
            last_fuel: None,
        }))
    }
}

// The host functions are defined by `engine::linker`, which is where the calling convention and the gate live. This
// module keeps the engine: one `Store`, one `Instance`, and the budget applied to a call.

/// Shares a built engine.
#[must_use]
pub fn shared(backend: WasmtimeBackend) -> Arc<WasmtimeBackend> {
    Arc::new(backend)
}

#[cfg(test)]
#[path = "wasmtime_tests.rs"]
mod tests;
