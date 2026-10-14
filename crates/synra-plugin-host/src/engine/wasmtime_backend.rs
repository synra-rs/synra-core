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

use super::executor::Epoch;
use super::types::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, Enforcement, PluginInstance,
    WasmBackend, Work,
};

/// The crate's own version, which is the engine-version input to a compile cache key.
///
/// The engine's version is the crate's: `wasmtime` is pinned in `Cargo.toml`, so a change to it is a change to the
/// build rather than to a runtime value. A cache entry a rebuild cannot use is a miss, which is a recompilation and
/// not a crash.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How much host stack a wasm frame may use, in bytes.
const MAX_WASM_STACK: usize = 512 * 1024;

/// How much address space is reserved per linear memory.
///
/// Reserved rather than committed: the reservation costs nothing until it is touched, and making it explicit stops the
/// engine from deciding on its own how much address space a plugin's memory may claim.
const MEMORY_RESERVATION: u64 = 64 * 1024 * 1024;

/// How much a memory may grow by in one step before the engine re-reserves.
const MEMORY_RESERVATION_FOR_GROWTH: u64 = 2 * 1024 * 1024;

/// The configuration the security baseline requires.
///
/// Every option here is one that decides what a guest may cost the host.
#[must_use]
pub fn engine_config(kind: BackendKind) -> Config {
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
    config.native_unwind_info(false);

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
}

impl CompiledArtifact for EngineArtifact {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn digest(&self) -> &str {
        &self.digest
    }
}

/// What an instance's store holds.
struct StoreData {
    /// The ceiling a growth is measured against, kept here because the engine's limiter does not report it back.
    ceiling: usize,
    /// Set when a growth the budget refused was attempted, so a call can report *why* it trapped rather than a
    /// generic trap the plugin author cannot act on.
    memory_refused: bool,
    limits: StoreLimits,
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
pub struct EngineInstance {
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
        }

        // ── Layer 3: memory ──
        if let Some(ceiling) = budget.max_memory_growth {
            let wanted = usize::try_from(ceiling).unwrap_or(usize::MAX);
            self.store.data_mut().ceiling = wanted;
            self.store.data_mut().limits = StoreLimitsBuilder::new().memory_size(wanted).build();
            self.ceiling = ceiling;
        }
        self.store.data_mut().memory_refused = false;

        match self.dispatch(work) {
            Ok(outcome) => Ok(outcome),
            Err(failure) => Ok(failure.into_outcome(budget, self.store.data().memory_refused)),
        }
    }
}

impl EngineInstance {
    /// Looks up the export and calls it.
    fn dispatch(&mut self, work: &Work) -> Result<CallOutcome, CallFailure> {
        let interface = work.interface();
        let function = work.function();
        let arguments = arguments_of(work);

        let export = self
            .instance
            .get_func(&mut self.store, export_name(interface, function))
            .ok_or(CallFailure::MissingExport { interface, function })?;
        let mut export = export;

        let params = arguments.iter().map(typing).collect::<Vec<_>>();
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

/// The name an export is reached by in a compiled component.
///
/// # Why this is spelled out rather than assumed
///
/// A component's exports are keyed by their *interface-qualified* name, not by the bare function: the contract's
/// `lifecycle.activate` is reached as `synra:plugin/lifecycle@1.0.0#activate`. A lookup on the bare name finds nothing,
/// and the symptom is a call that reports "the component does not export activate" for a component that plainly does —
/// which is a plugin author's problem to have and should not be the host's to invent.
///
/// The package and version come from [`crate::host_surface`], which `build.rs` regenerates from the contract, so a
/// version bump in `wit/synra-plugin.wit` cannot leave this behind.
#[must_use]
pub fn export_name(interface: &str, function: &str) -> String {
    // Both halves come from the generated table, which `build.rs` regenerates from `wit/synra-plugin.wit`: a version
    // bump in the contract cannot leave this behind, because the constant it is read from changes with it.
    format!(
        "{}@{}/{}#{function}",
        crate::host_surface::PACKAGE,
        crate::host_surface::PACKAGE_VERSION,
        interface,
    )
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
fn typing(argument: &String) -> Val {
    Val::String(argument.clone())
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
    /// # Errors
    ///
    /// [`BackendError::Engine`] when the engine refuses the configuration, which is a build-time problem reported
    /// rather than panicked on.
    pub fn new(kind: BackendKind) -> Result<Self, BackendError> {
        Self::with_epoch(kind, Epoch::new())
    }

    /// Builds an engine that shares an executor's epoch.
    ///
    /// # Why the epoch is passed rather than made here
    ///
    /// Because a deadline is only reached if something advances the counter. An engine with an epoch of its own would
    /// be an engine whose deadlines never fire — a wall-clock budget that silently does nothing, which is the failure
    /// this whole layer exists to make impossible.
    ///
    /// # Errors
    ///
    /// As [`WasmtimeBackend::new`].
    pub fn with_epoch(kind: BackendKind, epoch: Epoch) -> Result<Self, BackendError> {
        let engine = Engine::new(&engine_config(kind)).map_err(|error| BackendError::Engine {
            detail: format!("the engine refused its configuration: {error}"),
        })?;
        Ok(Self { engine, kind, epoch })
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
        Enforcement::full()
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

        let digest = super::scripted::digest_of(plugin_id, wasm);
        Ok(Box::new(EngineArtifact { component, digest, kind: self.kind, imports }))
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
                // A ceiling of zero until a budget says otherwise, so an instance created outside a call cannot grow
                // at all. A store that started unlimited and was limited later is one a start function could escape.
                ceiling: 0,
                memory_refused: false,
                limits: StoreLimitsBuilder::new().memory_size(0).build(),
            },
        );
        store.limiter(|data| data as &mut dyn wasmtime::ResourceLimiter);
        // One tick, so a store handed to a call without a budget still cannot run for ever.
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();

        let mut linker: Linker<StoreData> = Linker::new(&self.engine);
        define_host(&mut linker).map_err(|error| BackendError::Engine {
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

/// Defines the host functions this build provides.
///
/// # What is defined, and what is not
///
/// Nothing yet, and that is a deliberate refusal rather than an omission. Every function the contract declares moves
/// strings across the component-model boundary, and the *bindings* are what know that convention: a hand-written
/// definition would be a second implementation of it, in the one place where getting it wrong means reading a plugin's
/// argument from the wrong offset. `crate::host_surface::HOST_FUNCTIONS` is the table those bindings will be generated
/// from, and until they are, a component that imports one of these fails to **instantiate** with the import named.
///
/// That is the failure this design wants: a link error a plugin author can read, at the moment the plugin is loaded,
/// rather than a call that quietly does nothing.
fn define_host(_linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    Ok(())
}

/// Shares a built engine.
#[must_use]
pub fn shared(backend: WasmtimeBackend) -> Arc<WasmtimeBackend> {
    Arc::new(backend)
}

#[cfg(test)]
#[path = "wasmtime_tests.rs"]
mod tests;
