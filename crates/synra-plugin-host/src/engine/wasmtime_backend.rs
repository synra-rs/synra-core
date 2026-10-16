//! The real engine: `wasmtime`, configured the way the design document's security baseline requires.
//!
//! # What this module is for
//!
//! Everything else in [`crate::engine`] decides *what may happen*; this is what makes it happen. It compiles a
//! component, arms an instruction budget and a wall-clock deadline on the store, enforces a memory ceiling, and reports
//! what the guest did.
//!
//! # The configuration is the security boundary
//!
//! A default `wasmtime::Config` is a general-purpose engine. The options this module sets are the ones that decide what
//! a guest may cost the host, and each says which way it is set and why — see [`engine_config`]. The rest are the
//! engine's own defaults, which are the *restrictive* defaults for a build that enables only the features in this
//! crate's manifest: no threads, no SIMD, no garbage collector and no custom page sizes, because a proposal whose
//! supporting feature is not compiled in cannot be turned on.
//!
//! # Why thread and GC options are not spelled out
//!
//! Because in this version of the engine those setters exist only when the corresponding feature is enabled, so a host
//! that wants to say "no threads" says it by not depending on `wasmtime/threads`. That statement is in this crate's
//! `Cargo.toml` rather than here, which is where a dependency's features belong — and a reader asking "can a plugin
//! spawn a thread?" finds the answer by looking at what was enabled rather than at what was disabled.
//!
//! # What is not here yet
//!
//! The host functions. Every function the contract declares moves strings across the *component model's* boundary, and
//! the generated bindings are what know that convention: a hand-written definition would be a second implementation of
//! it, in the one place where getting it wrong means reading a plugin's argument from the wrong offset.
//!
//! So a component that imports a host function fails to **instantiate**, with the missing import named — a link-time
//! refusal rather than a silent hole, and the reason [`WasmtimeBackend::compile`] reports what a component imports
//! before it hands back an artefact at all.

use std::sync::Arc;
use std::time::Duration;

use wasmtime::component::{Component, Instance, Linker, Val};
use wasmtime::{Config, Engine, OptLevel, Store, StoreLimits, StoreLimitsBuilder};

use super::executor::{Epoch, EpochTicker};
use super::types::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, Enforcement, PluginInstance,
    WasmBackend, Work,
};

/// The crate's own version, which is the engine-version input to a compile cache key.
///
/// The engine's version is the crate's: `wasmtime` is pinned in `Cargo.toml`, so a change to it is a change to the
/// build rather than to a runtime value. A cache entry a rebuild cannot use is a miss, which is a recompilation and
/// not a crash.
pub(crate) const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How much host stack a wasm frame may use, in bytes.
const MAX_WASM_STACK: usize = 512 * 1024;

/// How much address space is reserved per linear memory.
///
/// Reserved rather than committed: the reservation costs nothing until it is touched, and making it explicit stops the
/// engine from deciding on its own how much address space a plugin's memory may claim.
const MEMORY_RESERVATION: u64 = 64 * 1024 * 1024;

/// How much a memory may grow by in one step before the engine re-reserves.
const MEMORY_RESERVATION_FOR_GROWTH: u64 = 2 * 1024 * 1024;

/// The memory ceiling an instance gets before a call replaces it with the plugin's own quota.
///
/// Sixteen mebibytes, and the number is not a budget: it is what a component's own declared minimum has to fit inside
/// for the instance to be creatable at all. A store that started at zero could not instantiate a module that declares
/// even one page — a plugin that never runs, rather than a plugin that cannot grow. What a *call* may reach is the
/// budget's, which is applied before the guest runs and is the number a hostile allocation meets.
const INSTANTIATION_CEILING: usize = 16 * 1024 * 1024;

/// Ticks that will not be reached, for a call whose budget names no wall clock.
///
/// ★ Why not `u64::MAX`, which is the obvious way to say "no deadline".
///
/// Because wasmtime **adds** the deadline to the current epoch, and `u64::MAX` overflows that addition — inside the
/// library, as a panic: `attempt to add with overflow` in `wasmtime/src/runtime/store.rs`. The disarm value therefore has
/// to leave room for the counter, which is the sort of thing only running it teaches.
///
/// At the executor's ten-millisecond period this is about three hundred and fifty years, so it is unreachable by any run
/// of any program, and the arithmetic cannot overflow.
const NO_DEADLINE_TICKS: u64 = 1 << 40;

/// The configuration the security baseline requires.
///
/// Every option here is one that decides what a guest may cost the host.
#[must_use]
pub(crate) fn engine_config(kind: BackendKind) -> Config {
    let mut config = Config::new();

    // ── The component model, which is what the contract is written in ──
    config.wasm_component_model(true);

    // ── Interruption: both mechanisms, because they catch different things ──
    //
    // Fuel is the instruction budget: a loop in pure arithmetic is stopped by it, deterministically. It does **not**
    // stop a guest that is blocked inside a host call, because such a guest consumes no instructions at all — and that
    // is what the epoch is for. A host with only one of the two has a bound that anything can step around.
    config.consume_fuel(true);
    config.epoch_interruption(true);

    // ── Resources ──
    config.max_wasm_stack(MAX_WASM_STACK);
    config.memory_reservation(MEMORY_RESERVATION);
    config.memory_reservation_for_growth(MEMORY_RESERVATION_FOR_GROWTH);
    // No dense image: the copy it enables is what a large reservation would otherwise pay for on every instantiation.
    config.memory_guaranteed_dense_image_size(0);

    // ── Compilation ──
    //
    // Winch is the baseline compiler: quicker to produce code, slower to run it. That is the trade a phone makes,
    // where the build happens while a user waits and the run happens once.
    config.cranelift_opt_level(match kind {
        BackendKind::WasmtimeWinch => OptLevel::None,
        _ => OptLevel::Speed,
    });

    // ── Diagnostics that cost every call ──
    //
    // A backtrace is built when a trap happens, which is the moment an attacker would most like to be expensive. The
    // kernel's log records that a trap occurred and which plugin it was; a per-frame backtrace is a debugging aid that
    // is turned on deliberately.
    config.wasm_backtrace(false);

    // ★ Unwind information is deliberately **not** turned off, and it is the one baseline option the engine refuses to
    // let a host disable on Windows: the platform's own exception handling needs it. A build that turned it off would
    // fail right here, with a message naming the option — a better outcome than one that built and then crashed in a
    // way nobody could read.
    config
}

/// A component that has been compiled and checked.
pub struct EngineArtifact {
    component: Component,
    digest: String,
    /// The component's true kind, so an artefact from another backend cannot be run by this one.
    kind: BackendKind,
    /// The interfaces the component imports, as `interface/function` pairs.
    ///
    /// Read from the component's own type rather than from a manifest: what is checked is what the artifact actually
    /// imports, which is the difference between a claim and a fact.
    imports: Vec<String>,
    /// The interfaces it exports, which is how the contract's four entry points are reached.
    exports: Vec<String>,
}

impl std::fmt::Debug for EngineArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineArtifact")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .field("imports", &self.imports)
            .finish_non_exhaustive()
    }
}

impl EngineArtifact {
    /// What the component imports.
    #[must_use]
    pub fn imports(&self) -> &[String] {
        &self.imports
    }

    /// What the component exports.
    #[must_use]
    pub fn exports(&self) -> &[String] {
        &self.exports
    }
}

impl CompiledArtifact for EngineArtifact {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    /// What the component's own type says it imports.
    ///
    /// Already read at compile time and already checked against the host's table — the linker refuses to instantiate a
    /// component naming a function this build does not provide. Exposing it is what lets the *kernel* make the other
    /// check, about the plugin's own capabilities, without knowing which engine produced the artifact.
    fn imports(&self) -> &[String] {
        &self.imports
    }
}

/// What an instance's store holds.
pub(crate) struct StoreData {
    /// The ceiling a growth is measured against, kept here because the engine's limiter does not report it back.
    ceiling: usize,
    /// Set when a growth the budget refused was attempted, so a call can report *why* it trapped rather than a
    /// generic trap the plugin author cannot act on.
    memory_refused: bool,
    limits: StoreLimits,
    /// The plugin whose calls this instance makes, when the host gave it one.
    ///
    /// `None` for an instance the host built without a session, which is the only way a host function can be reached
    /// without a gate — and the answer there is a refusal rather than a call.
    pub(crate) session: Option<Box<dyn std::any::Any + Send + Sync>>,
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

/// One instantiated plugin.
pub(crate) struct EngineInstance {
    store: Store<StoreData>,
    instance: Instance,
    kind: BackendKind,
    host_calls: u64,
    deadline_epoch: Option<u64>,
    /// How much the plugin's memories have been told they may reach, so `memory_bytes` answers with the number the
    /// ceiling was enforced against rather than with a guess.
    ceiling: u64,
}

impl std::fmt::Debug for EngineInstance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineInstance")
            .field("kind", &self.kind)
            .field("host_calls", &self.host_calls)
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
        u64::try_from(self.store.data().ceiling).unwrap_or(u64::MAX).min(self.ceiling)
    }

    fn host_calls(&self) -> u64 {
        self.host_calls
    }

    fn deadline_epoch(&self) -> Option<u64> {
        self.deadline_epoch
    }

    fn call(&mut self, work: &Work, budget: CallBudget) -> Result<CallOutcome, BackendError> {
        // ── Layer 1: the instruction budget ──
        if let Some(fuel) = budget.fuel {
            self.store.set_fuel(fuel).map_err(|error| BackendError::Engine {
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
            // ★ And with no time limit, the deadline has to be **disarmed** rather than left alone.
            //
            // Instantiation arms `set_epoch_deadline(1)` — a single tick, so that a start function cannot run away before
            // the first call sets a budget. Nothing put it back: a call whose budget asked for no wall clock kept the
            // deadline of one, so the executor's next epoch advance interrupted it and `classify` reported
            // `Timeout { after: 0ns }` — a timeout for a budget that had none.
            //
            // It only happened under load, because the interrupt needs the epoch to advance while the call is in flight,
            // which is why it read as a flake: a plugin that returned immediately was reported as having timed out, in a
            // suite run and never on its own. `u64::MAX` ticks is the same statement as "no deadline" using the only
            // vocabulary the store offers, and clearing `deadline_epoch` keeps the accessor honest about it.
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

        match self.dispatch(work) {
            Ok(outcome) => Ok(outcome),
            Err(failure) => Ok(failure.into_outcome(budget, self.store.data().memory_refused)),
        }
    }
}

impl EngineInstance {
    /// Looks up the export and calls it.
    ///
    /// # The two spellings a component may use
    ///
    /// A world exports `synra:plugin/lifecycle@1.0.0` as a **nested instance**, and the function inside it is reached
    /// through that; a component may also export the same interface **flattened**, as one name per function. Both are
    /// what a real toolchain emits, so both are reached here — and the interface name is not guessable from the two
    /// strings, which is why a component built against another version of the contract is not reached at all rather
    /// than reached wrongly.
    fn dispatch(&mut self, work: &Work) -> Result<CallOutcome, CallFailure> {
        let interface = work.interface();
        let function = work.function();
        let arguments = arguments_of(work);

        // ★ The lookup is two steps, and the first version of this got it wrong in a way that only showed up when a
        // real component was instantiated: a world exports `synra:plugin/lifecycle@1.0.0` as a **nested instance**, and
        // `wasmtime` does not flatten one into `<interface>#<function>`. The name of the instance is one export and the
        // name of the function inside it is another, and the second is only reachable *through* the first — which is
        // `Instance::get_export_index` with the instance's index, exactly as the API's own documentation shows.
        //
        // A component may also export the same interface flattened, one name per function, because that is what some
        // toolchains emit. Both are tried, in that order, and the flattened form is the fallback rather than the first
        // attempt — because the nested form is what a component built from the WIT file has.
        let flat = export_name(interface, function);
        // ★ The *fully qualified* interface name, not the bare one: `Work::interface` answers `"lifecycle"` because
        // that is the interface's own name, and an export is keyed by `synra:plugin/lifecycle@1.0.0` because an
        // interface name is only unique within its package and version. Looking up `"lifecycle"` finds nothing, and the
        // symptom is a component reporting that it does not export a function it plainly does.
        let qualified = interface_name(interface);
        let nested = self
            .instance
            .get_export_index(&mut self.store, None, &qualified)
            .and_then(|instance_index| {
                self.instance.get_export_index(&mut self.store, Some(&instance_index), function)
            })
            .and_then(|index| self.instance.get_func(&mut self.store, index));
        let export = match nested {
            Some(export) => export,
            None => self
                .instance
                .get_func(&mut self.store, flat)
                .ok_or(CallFailure::MissingExport { interface, function })?,
        };

        let params = arguments.iter().map(|argument| typing(argument)).collect::<Vec<_>>();
        let mut results = Vec::new();
        export
            .call(&mut self.store, &params, &mut results)
            .map_err(CallFailure::Trap)?;
        // `post-return` is the contract's half of the calling convention: a guest that allocated a string for its
        // answer expects the host to say when it may be freed. Skipping it leaks the answer in the guest's memory for
        // as long as the instance lives, which for a pooled instance is every call after this one.
        export.post_return(&mut self.store).map_err(CallFailure::Trap)?;
        self.host_calls = self.host_calls.saturating_add(1);

        Ok(CallOutcome::Ok(render(&results)))
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
    fn into_outcome(self, budget: CallBudget, memory_refused: bool) -> CallOutcome {
        match self {
            Self::MissingExport { interface, function } => CallOutcome::Trap {
                detail: format!("the component does not export {interface}.{function}"),
            },
            Self::Trap(error) => classify(&error, budget, memory_refused),
        }
    }
}

/// Turns an engine error into the outcome the caller handles.
///
/// # Why this is a function and not a `match` at the call site
///
/// Because the three limits produce three *different* errors, and each has a different thing a user can do: raise the
/// instruction budget, raise the time limit, or give the plugin more memory. Collapsing them into "the plugin failed"
/// would put the work of telling them apart on whoever reads the message.
fn classify(error: &wasmtime::Error, budget: CallBudget, memory_refused: bool) -> CallOutcome {
    if memory_refused {
        return CallOutcome::MemoryExceeded { limit: budget.max_memory_growth.unwrap_or(0) };
    }
    let text = format!("{error:#}");
    let lowered = text.to_lowercase();
    if lowered.contains("epoch") || lowered.contains("interrupt") {
        return CallOutcome::Timeout { after: budget.timeout.unwrap_or(Duration::ZERO) };
    }
    if lowered.contains("fuel") {
        return CallOutcome::FuelExhausted { fuel: budget.fuel.unwrap_or(0) };
    }
    CallOutcome::Trap { detail: text }
}

/// The arguments a call's parameters carry, in the contract's order.
///
/// Every parameter of every function in the contract is a string, an `option<string>` or a list of strings, so this is
/// a short table rather than a general type mapping.
fn arguments_of(work: &Work) -> Vec<String> {
    match work {
        Work::Deactivate => Vec::new(),
        Work::Activate { config_json } => vec![config_json.clone()],
        Work::Migrate { from_version, to_version } => vec![from_version.clone(), to_version.clone()],
        Work::Tick { tick_json } => vec![tick_json.clone()],
        Work::CanHandle { item_json } => vec![item_json.clone()],
        Work::Execute { action, args_json } => vec![action.clone(), args_json.clone()],
        Work::InvokeAction { name, args_json } => vec![name.clone(), args_json.clone()],
    }
}

/// The component-model type of one argument.
fn typing(argument: &str) -> Val {
    Val::String(argument.to_owned())
}

/// Renders what the guest returned.
fn render(results: &[Val]) -> String {
    match results.first() {
        Some(Val::String(text)) => text.clone(),
        Some(Val::Bool(flag)) => flag.to_string(),
        Some(Val::U32(number)) => number.to_string(),
        Some(Val::U64(number)) => number.to_string(),
        // A guest that returned nothing produced no payload, which is an answer rather than a failure: the contract's
        // `deactivate` returns nothing at all.
        None | Some(_) => String::new(),
    }
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
    /// budget armed a deadline on a counter that would never reach it, so a guest that blocked inside a host call ran
    /// until it finished or forever.
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

        Ok(Self { engine, kind, epoch, ticker: None })
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
        Enforcement { precompile: false, ..Enforcement::full() }
    }

    fn engine_version(&self) -> &str {
        ENGINE_VERSION
    }

    fn compile(&self, wasm: &[u8], plugin_id: &str) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        if wasm.is_empty() {
            return Err(BackendError::Compile { detail: "the artifact is empty".to_owned() });
        }
        let component = Component::new(&self.engine, wasm).map_err(|error| BackendError::Compile {
            detail: format!("{error:#}"),
        })?;

        // ★ The import check happens here rather than at the first call. A component importing a function this host
        // does not provide is one built against a host that has it, and letting it link would move the failure to a
        // call site far from its cause. The names come from the component's own type, so what is checked is what the
        // artifact imports rather than what its manifest claims.
        let component_type = component.component_type();
        let mut imports = Vec::new();
        for (name, _) in component_type.imports(&self.engine) {
            imports.push(name.to_string());
        }
        imports.sort();

        // ★ The *exports* are checked here too, and for the same reason the imports are: a component that does not
        // export the three interfaces the contract requires is one built against a different contract, and a user
        // should be told that when the plugin is loaded rather than when they first share something with it.
        let mut exports = Vec::new();
        for (name, _) in component_type.exports(&self.engine) {
            exports.push(name.to_string());
        }
        exports.sort();
        // ★ The interface a plugin cannot be without is checked here, and the one it *is* checked for is `lifecycle`:
        // `activate` is what the host calls before anything else, so a component without it is one that would be
        // installed and then fail at the first use. `share` and `actions` are optional in practice — a plugin that
        // handles nothing and declares no action exports empty instances — so requiring them would refuse components
        // the contract allows.
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
        Ok(Box::new(EngineArtifact { component, digest, kind: self.kind, imports, exports }))
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
        let Some(artifact) = (compiled as &dyn std::any::Any).downcast_ref::<EngineArtifact>() else {
            return Err(BackendError::Engine {
                detail: format!(
                    "a {} artefact cannot be run by the {} backend",
                    compiled.kind(),
                    self.kind
                ),
            });
        };
        let _ = backend;

        let mut store = Store::new(
            &self.engine,
            StoreData {
                // ★ Sixteen mebibytes at instantiation, and the reason it is not zero: a module's own declared minimum
                // has to fit, or the component cannot be created at all — which is a plugin that never runs rather than
                // a plugin that cannot grow. What a *call* may reach is the budget's, applied below, and that is the
                // number a hostile allocation is measured against.
                ceiling: INSTANTIATION_CEILING,
                memory_refused: false,
            // Conservative in the permissive direction for construction only: `call` sets this before dispatching, and an
            // instance that never dispatched is one no guest code ran in.
            side_effects: true,
                session: None,
                limits: StoreLimitsBuilder::new().memory_size(INSTANTIATION_CEILING).build(),
            },
        );
        store.limiter(|data| data as &mut dyn wasmtime::ResourceLimiter);
        // One tick, so a store handed to a call without a budget still cannot run for ever.
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();

        let mut linker: Linker<StoreData> = Linker::new(&self.engine);
        crate::engine::linker::define(&mut linker).map_err(|error| BackendError::Engine {
            detail: format!("the host functions could not be defined: {error:#}"),
        })?;

        let instance = linker
            .instantiate(&mut store, &artifact.component)
            .map_err(|error| BackendError::Instantiate { detail: format!("{error:#}") })?;

        Ok(Box::new(EngineInstance {
            store,
            instance,
            kind: self.kind,
            host_calls: 0,
            deadline_epoch: None,
            ceiling: 0,
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
