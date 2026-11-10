use super::{BackendError, BackendKind, CallBudget, CallOutcome, Work};

/// A component that has been compiled and can be instantiated repeatedly.
///
/// The engine's compiled artefact, behind a trait object: compiling once and instantiating many times is the whole
/// basis of the instance pool, and it is also what makes a compile cache worth having.
///
/// `Any` is a supertrait so a backend can recognise **its own** artefact: one from another engine is not something to
/// be instantiated, and the alternative to a type check is bytes that decode as instructions rather than fail. It is
/// also what lets a test read what a component imports without the backend having to expose a method for it.
pub trait CompiledArtifact: Send + Sync + std::any::Any {
    /// The backend that produced it.
    fn kind(&self) -> BackendKind;

    /// A digest of the compiled form, for a cache key.
    fn digest(&self) -> &str;

    /// The host functions the artifact imports, as the component's own type reports them.
    ///
    /// # ★ Why this is on the trait and not only on `EngineArtifact`
    ///
    /// Because the load-time check that needs it — "every function this artifact imports is one its capabilities cover"
    /// — lives in the kernel, which holds a `Box<dyn CompiledArtifact>` and cannot name the concrete type without
    /// depending on the engine it happens to be running.
    ///
    /// The check itself is [`host_surface::undeclared_imports`](crate::host_surface::undeclared_imports): written,
    /// tested, and called by nothing in production, because the pipeline that uses it
    /// ([`verify`](crate::verify::verify)) has no caller either. An artifact importing a host function its manifest never
    /// declared was loaded and run, and the first sign of it would have been a call refused at the gate — for a reason
    /// the author could not act on.
    ///
    /// # Why the default is empty
    ///
    /// A backend whose artifacts have no imports has nothing to report. `ScriptedArtifact` overrides it, so a test can
    /// express an artifact that imports something — which is the condition this method exists to let a caller check.
    fn imports(&self) -> &[String] {
        &[]
    }
}

/// One instantiated plugin, ready to be called.
///
/// # Why `call` takes `&mut self` and is synchronous
///
/// A Wasm store is mutable state — fuel, memory, the guest's globals — and two threads calling one instance at once is
/// a data race by construction. And an engine's execution is a blocking call: it does not yield, and running it on an
/// asynchronous worker is the mistake the design document names, because a guest that blocks stops every other task on
/// that thread. So an instance is owned by one calling thread, and [`crate::engine::executor::WasmExecutor`] is what
/// gives it one.
pub trait PluginInstance: Send {
    /// The backend that made it.
    fn kind(&self) -> BackendKind;

    /// How many bytes of memory the instance is holding.
    fn memory_bytes(&self) -> u64;

    /// How many host calls this instance has made.
    fn host_calls(&self) -> u64;

    /// Runs one entry point under a budget.
    ///
    /// # Errors
    ///
    /// [`BackendError`] when the call could not be started at all — a missing export, a dead engine. A guest that
    /// failed *while running* is a [`CallOutcome`], not an error: a trap is something the caller decides about.
    fn call(&mut self, work: &Work, budget: CallBudget) -> Result<CallOutcome, BackendError>;

    /// The epoch value the most recent call was given, or `None` when the backend has no epoch.
    ///
    /// Exposed because it is the only way to test that a deadline was actually armed on the store: a timeout test that
    /// only asserted "it returned `Timeout`" would pass against a backend that refused everything.
    fn deadline_epoch(&self) -> Option<u64> {
        None
    }

    /// Fuel the most recent call consumed, when the engine counts it.
    ///
    /// `None` for a backend with no instruction counter (the scripted one), and for a call that never started. It is a
    /// reading of what the guest **spent**, not of the budget it was given: the two differ by the remainder, and the
    /// remainder is the engine's business.
    fn last_fuel_consumed(&self) -> Option<u64> {
        None
    }

    /// Hands this instance the session a host call is authorised against.
    ///
    /// # ★ Why this is a setter rather than a parameter of `instantiate`
    ///
    /// Because the session is **per call**, not per instance, and the pieces it needs — which plugin, what it was
    /// granted, which budget, which host — are held by the caller that knows the plugin, not by the backend that knows
    /// the engine. Threading them through `instantiate` would make every backend's signature carry four arguments it
    /// does not read, for a value only the Wasm backend can use.
    ///
    /// # Why the default does nothing
    ///
    /// Because a backend with no host functions to authorise has nothing to install it into. The scripted backend is
    /// the case: it answers from a table and never reaches a guest, so a session is not something it can be given. A
    /// default is right here rather than a required method, because the alternative is every such backend writing an
    /// empty body to satisfy a compiler.
    ///
    /// # The invariant this exists to keep
    ///
    /// An instance that has **not** been given a session refuses every host call — see `linker::run`, which answers a
    /// refusal rather than running a function ungated. So a caller that forgets to call this gets a plugin that cannot
    /// call the host, not a plugin that can call it without a check. That is the safe direction for the omission.
    fn set_session(&mut self, session: crate::engine::session::LinkerSession) {
        // Named rather than `_`, so a backend that overrides this knows what it is being handed.
        let _ = session;
    }
}
