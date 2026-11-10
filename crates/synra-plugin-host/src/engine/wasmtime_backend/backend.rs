use std::sync::Arc;

use wasmtime::component::Linker;
use wasmtime::{Engine, Store};

use crate::engine::executor::{Epoch, EpochTicker, ticks_for};
use crate::engine::types::{
    Backend, BackendError, BackendKind, CompiledArtifact, Enforcement, PluginInstance, WasmBackend,
};

use super::config::{INSTANTIATION_FUEL, INSTANTIATION_TIMEOUT};
use super::instance::EngineInstance;
use super::{ENGINE_VERSION, EngineArtifact, StoreData, compile, engine_config, imports, interface_name};

/// An engine, and the configuration it was built with.
#[derive(Clone)]
pub struct WasmtimeBackend {
    engine: Engine,
    compiler: Arc<compile::Compiler>,
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
            compiler: Arc::new(compile::Compiler::default()),
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
        if wasm.len() > crate::engine::MAX_COMPONENT_BYTES {
            return Err(BackendError::Compile {
                detail: format!(
                    "the artifact is {} bytes, and the largest this host compiles is {}",
                    wasm.len(),
                    crate::engine::MAX_COMPONENT_BYTES
                ),
            });
        }
        let component = self.compiler.compile(&self.engine, wasm)?;

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

        let digest = crate::engine::scripted::digest_of(plugin_id, wasm);
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

        Ok(Box::new(EngineInstance::new(store, instance, self.kind)))
    }
}

/// Shares a built engine.
#[must_use]
pub fn shared(backend: WasmtimeBackend) -> Arc<WasmtimeBackend> {
    Arc::new(backend)
}
