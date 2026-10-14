//! What a plugin call *is*, and what it can come back as.
//!
//! # Why this vocabulary is separate from any engine
//!
//! Because the two questions this crate answers — may this call happen, and how much of it may happen — are answered
//! before an engine exists. An execution layer written against `wasmtime` types would make every one of those answers
//! untestable in an environment where the engine does not build, and those are precisely the answers that get got
//! wrong. The engine sits behind [`WasmBackend`], and everything here is the shape of the conversation with it.

use std::fmt;

/// Which engine compiles and runs a plugin's artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum BackendKind {
    /// The full `wasmtime` engine with its JIT. The desktop default: fastest to run, slowest to build.
    WasmtimeCranelift,
    /// `wasmtime` with the Winch baseline compiler: quicker to compile, slower to run.
    WasmtimeWinch,
    /// `wasmtime`'s interpreter, for targets where a JIT is not allowed.
    WasmtimePulley,
    /// A pure-Rust interpreter, for the smallest binary.
    Wasmi,
    /// A backend that executes nothing and answers from a script.
    ///
    /// ★ Not a mock in the testing sense — it is the *only* backend that exists when the `wasm-runtime` feature is off,
    /// and it is what makes the pool, the budget accounting and the isolation policy testable without an engine. A
    /// backend that only ever said "ok" would prove nothing; this one is driven by a table of answers, so a test can
    /// ask for a trap and see the trap reach the caller.
    Scripted,
}

impl BackendKind {
    /// Every backend, for a caller that lists them.
    pub const ALL: &'static [Self] = &[
        Self::WasmtimeCranelift,
        Self::WasmtimeWinch,
        Self::WasmtimePulley,
        Self::Wasmi,
        Self::Scripted,
    ];

    /// The backend a platform runs by default.
    ///
    /// # Why Android is not the desktop default
    ///
    /// Because package size matters there and a baseline compiler is the compromise the design document names: a JIT
    /// costs build time on a phone and an interpreter costs every call. Neither costs anything here, so this is a
    /// table rather than a decision.
    #[must_use]
    pub const fn default_for(platform: HostKind) -> Self {
        match platform {
            HostKind::Desktop => Self::WasmtimeCranelift,
            HostKind::Mobile => Self::WasmtimeWinch,
            HostKind::Headless => Self::WasmtimeCranelift,
        }
    }

    /// A stable name, for a cache key and a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmtimeCranelift => "wasmtime-cranelift",
            Self::WasmtimeWinch => "wasmtime-winch",
            Self::WasmtimePulley => "wasmtime-pulley",
            Self::Wasmi => "wasmi",
            Self::Scripted => "scripted",
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What kind of machine the host is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostKind {
    /// A window, a mouse and a filesystem the user can see.
    Desktop,
    /// A phone or a tablet.
    Mobile,
    /// No interface at all: a CLI, a daemon, a test.
    Headless,
}

impl HostKind {
    /// A stable name, which is what `env-host-kind` answers with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
            Self::Headless => "headless",
        }
    }
}

impl fmt::Display for HostKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One entry point the host calls on a plugin.
///
/// # Why this is four variants and not a string
///
/// Because these are the *only* things a host may call, and they are the only four the contract exports. A free string
/// would let a typo name an export that does not exist, and the failure would be a link error at instantiation time
/// rather than a value that cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Work {
    /// `lifecycle.activate`, with the plugin's own settings as JSON.
    Activate {
        /// The plugin's settings, as the JSON object the store holds.
        config_json: String,
    },
    /// `lifecycle.deactivate`. Carries nothing: the contract's own signature has no return value either.
    Deactivate,
    /// `lifecycle.migrate`.
    Migrate {
        /// The version being left.
        from_version: String,
        /// The version being arrived at.
        to_version: String,
    },
    /// `lifecycle.on-tick`, with whatever the timer wanted to say.
    Tick {
        /// The tick's payload, as JSON.
        tick_json: String,
    },
    /// `share.can-handle`. Runs without side effects, and before the user has chosen anything.
    CanHandle {
        /// The share, as JSON.
        item_json: String,
    },
    /// `share.execute`.
    Execute {
        /// The action `can-handle` proposed.
        action: String,
        /// Its arguments, as JSON.
        args_json: String,
    },
    /// `actions.invoke`, for another plugin calling this one's action.
    InvokeAction {
        /// The action's name.
        name: String,
        /// Its arguments, as JSON.
        args_json: String,
    },
}

impl Work {
    /// The interface the export belongs to.
    #[must_use]
    pub const fn interface(&self) -> &'static str {
        match self {
            Self::Activate { .. } | Self::Deactivate | Self::Migrate { .. } | Self::Tick { .. } => "lifecycle",
            Self::CanHandle { .. } | Self::Execute { .. } => "share",
            Self::InvokeAction { .. } => "actions",
        }
    }

    /// The export's name within its interface.
    #[must_use]
    pub const fn function(&self) -> &'static str {
        match self {
            Self::Activate { .. } => "activate",
            Self::Deactivate => "deactivate",
            Self::Migrate { .. } => "migrate",
            Self::Tick { .. } => "on-tick",
            Self::CanHandle { .. } => "can-handle",
            Self::Execute { .. } => "execute",
            Self::InvokeAction { .. } => "invoke",
        }
    }

    /// Whether this call is allowed to have side effects.
    ///
    /// # Why the host enforces this rather than trusting the plugin
    ///
    /// `can-handle` runs for **every** plugin the router asks, before a user has chosen anything. A plugin that wrote a
    /// file, opened a browser or sent a message there would have done it for every share the user then cancelled. The
    /// contract says the function has no side effects; the host is what makes that true, by running it with a context
    /// whose action-shaped calls are refused.
    #[must_use]
    pub const fn allows_side_effects(&self) -> bool {
        !matches!(self, Self::CanHandle { .. })
    }
}

impl fmt::Display for Work {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.interface(), self.function())
    }
}

/// How much of one call a plugin may use.
///
/// # Why three limits and not one
///
/// They catch different things, and each catches something the others do not:
///
/// | A plugin that… | fuel | epoch | memory |
/// | --- | --- | --- | --- |
/// | loops forever | ✅ | ✅ | |
/// | calls a host function that blocks | | ✅ | |
/// | allocates until the machine swaps | | | ✅ |
///
/// A fuel limit alone is the trap that looks sufficient: a guest that never returns from a host call consumes no
/// instructions at all, so the wall clock is the only thing that ends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallBudget {
    /// Instructions this call may execute, or `None` for no limit.
    pub fuel: Option<u64>,
    /// How long this call may take, or `None` for no limit.
    pub timeout: Option<std::time::Duration>,
    /// How much the plugin's memory may grow during this call, in bytes, or `None` for no limit.
    pub max_memory_growth: Option<u64>,
}

impl CallBudget {
    /// The budget a plugin's quota asks for.
    ///
    /// Every field is taken from the quota rather than chosen here, so the number a user sees in a settings screen is
    /// the number the sandbox enforces.
    #[must_use]
    pub const fn from_quota(quota: &crate::quota::Quota) -> Self {
        Self {
            fuel: Some(quota.call_fuel),
            timeout: Some(quota.call_timeout()),
            max_memory_growth: Some(quota.max_memory_bytes),
        }
    }

    /// A budget with nothing limited, for a fixture.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self { fuel: None, timeout: None, max_memory_growth: None }
    }
}

/// What a call produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallOutcome {
    /// The call returned a value. Payloads crossing the boundary are JSON strings, per the contract.
    Ok(String),
    /// The plugin returned a structured failure. Not a bug: it is a thing the plugin handled and reported.
    Failed {
        /// One of the kernel's stable error codes.
        code: String,
        /// A sentence for a log.
        message: String,
    },
    /// The instruction budget ran out.
    FuelExhausted {
        /// The budget that ran out.
        fuel: u64,
    },
    /// The wall clock ran out, which is the only limit that stops a guest blocked inside a host call.
    Timeout {
        /// How long the call was given.
        after: std::time::Duration,
    },
    /// The memory limit was reached.
    MemoryExceeded {
        /// The limit that was reached.
        limit: u64,
    },
    /// The guest trapped: a panic, an out-of-bounds access, an illegal instruction.
    Trap {
        /// What the engine said, which is what a plugin author needs to see.
        detail: String,
    },
}

impl CallOutcome {
    /// Whether the call produced a value the caller can use.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// The payload, when there is one.
    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        match self {
            Self::Ok(payload) => Some(payload),
            _ => None,
        }
    }

    /// Whether this outcome is a reason to distrust the plugin rather than the call.
    ///
    /// # Why the distinction matters to health
    ///
    /// A plugin that returns `Failed` is working: it reached a decision and said so. A plugin that traps, times out or
    /// exhausts its fuel has done something the host had to stop, and a run of those is what the health model degrades
    /// on. Counting both the same way would fault a plugin for reporting an error, which is the behaviour asked of it.
    #[must_use]
    pub const fn is_misbehaviour(&self) -> bool {
        matches!(
            self,
            Self::FuelExhausted { .. } | Self::Timeout { .. } | Self::MemoryExceeded { .. } | Self::Trap { .. }
        )
    }

    /// A stable name, for a metric label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ok(_) => "ok",
            Self::Failed { .. } => "failed",
            Self::FuelExhausted { .. } => "fuel-exhausted",
            Self::Timeout { .. } => "timeout",
            Self::MemoryExceeded { .. } => "memory-exceeded",
            Self::Trap { .. } => "trap",
        }
    }
}

/// Why a plugin could not be compiled or instantiated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BackendError {
    /// The engine is not compiled into this build.
    ///
    /// Named separately from [`Self::Compile`] because the caller's next step is different: nothing about the artifact
    /// is wrong, and the build is what has to change.
    #[error("the {kind} backend is not compiled into this build")]
    BackendUnavailable {
        /// Which backend was wanted.
        kind: BackendKind,
    },

    /// The artifact is not a valid component, or is one this engine cannot compile.
    #[error("the artifact could not be compiled: {detail}")]
    Compile {
        /// What the engine said.
        detail: String,
    },

    /// The component imports something the host does not provide.
    ///
    /// ★ Refused at instantiation, not at the first call. A component importing an unknown function is one built
    /// against a host that has it, and letting it link would move the failure to a call site far from the cause.
    #[error("the component imports {import}, which this host does not provide")]
    UnknownImport {
        /// The import name, in full.
        import: String,
    },

    /// The component imports something the plugin was not granted.
    #[error("the component imports {import}, which needs {capability} and was not granted")]
    UngrantedImport {
        /// The import name.
        import: String,
        /// The capability it needs.
        capability: &'static str,
    },

    /// The component does not export an interface the contract requires.
    #[error("the component does not export {export}")]
    MissingExport {
        /// The interface that is missing.
        export: &'static str,
    },

    /// The instance could not be created: a missing memory, a start function that trapped.
    #[error("the instance could not be created: {detail}")]
    Instantiate {
        /// What the engine said.
        detail: String,
    },

    /// Creating another instance would exceed what the quota allows.
    #[error("the plugin already holds {live} instances and may hold {limit}")]
    TooManyInstances {
        /// How many exist.
        live: u32,
        /// What the quota allows.
        limit: u32,
    },

    /// The engine's own failure, which is not the plugin's fault.
    #[error("the engine failed: {detail}")]
    Engine {
        /// What it said.
        detail: String,
    },
}

/// What an engine can actually enforce.
///
/// # Why this is asked rather than assumed
///
/// A backend that cannot stop a runaway guest must not be given one. `wasmi` interprets and counts instructions, so it
/// can do fuel; an engine without epoch interruption cannot end a call blocked inside a host function. A host that
/// assumed the controls existed would run third-party code with no upper bound and believe it had one — so the
/// capability is a value the backend reports, and a caller that needs a limit it cannot get is a caller that refuses
/// the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Enforcement {
    /// Instruction counting.
    pub fuel: bool,
    /// Wall-clock interruption.
    pub epoch: bool,
    /// A memory ceiling.
    pub memory: bool,
    /// AOT precompilation.
    pub precompile: bool,
}

impl Enforcement {
    /// Everything a fully featured engine offers.
    #[must_use]
    pub const fn full() -> Self {
        Self { fuel: true, epoch: true, memory: true, precompile: true }
    }

    /// Whether this backend enforces everything a budget asks for.
    ///
    /// # Returns
    ///
    /// The first limit the backend cannot honour, so a refusal names the missing control rather than saying "no".
    #[must_use]
    pub const fn first_gap(&self, budget: &CallBudget) -> Option<&'static str> {
        if budget.fuel.is_some() && !self.fuel {
            return Some("an instruction budget");
        }
        if budget.timeout.is_some() && !self.epoch {
            return Some("a wall-clock limit");
        }
        if budget.max_memory_growth.is_some() && !self.memory {
            return Some("a memory ceiling");
        }
        None
    }
}

/// A component that has been compiled and can be instantiated repeatedly.
///
/// The engine's compiled artefact, behind a trait object: compiling once and instantiating many times is the whole
/// basis of the instance pool, and it is also what makes a compile cache worth having.
pub trait CompiledArtifact: Send + Sync {
    /// The backend that produced it.
    fn kind(&self) -> BackendKind;

    /// A digest of the compiled form, for a cache key.
    fn digest(&self) -> &str;
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
}

/// A backend shared by everything that uses it.
///
/// # Why a handle type rather than `Arc<dyn WasmBackend>` alone
///
/// Because an instance needs the backend that made it: its import table, its engine, its counters. An instance holding
/// a borrow would tie every instance's lifetime to the caller's stack; one holding a copy of a *concrete* backend would
/// be an instance of a different backend, which for [`crate::engine::scripted`] means a script table that is never
/// found. And the unsizing coercion from `Arc<Concrete>` to `Arc<dyn Trait>` cannot be named in a trait method's
/// `self` type, so the erasure happens in a constructor instead — one line, in one place, rather than at every call
/// site.
#[derive(Clone)]
pub struct Backend {
    inner: std::sync::Arc<dyn WasmBackend>,
}

impl Backend {
    /// Shares a backend.
    ///
    /// The coercion to a trait object happens here, which is the only place it can.
    pub fn new<T: WasmBackend + 'static>(backend: std::sync::Arc<T>) -> Self {
        Self { inner: backend }
    }

    /// The engine behind the handle.
    #[must_use]
    pub fn engine(&self) -> &dyn WasmBackend {
        self.inner.as_ref()
    }

    /// The same engine as its concrete type, when it is the one asked for.
    ///
    /// # Why this exists
    ///
    /// An instance has to reach its backend's own state — a script table, an engine, a counter — and the only handle it
    /// is given is this erased one. The alternative would be for every backend to thread its state into its instances
    /// through a constructor of its own, which is the same downcast written once per backend with no type check.
    ///
    /// The check is the type id, so a wrong type is `None` rather than a reinterpreted pointer.
    #[must_use]
    pub fn concrete<T: WasmBackend + 'static>(&self) -> Option<&T> {
        // `Any` as a supertrait, which is what makes this cast legal: a downcast needs a type id, and a type id is only
        // meaningful for a type that is `'static` — the same bound the trait already carries.
        (self.inner.as_ref() as &dyn std::any::Any).downcast_ref::<T>()
    }

    /// Which engine this is.
    #[must_use]
    pub fn kind(&self) -> BackendKind {
        self.inner.kind()
    }

    /// What this engine can enforce.
    #[must_use]
    pub fn enforcement(&self) -> Enforcement {
        self.inner.enforcement()
    }

    /// The engine's version.
    #[must_use]
    pub fn engine_version(&self) -> &str {
        self.inner.engine_version()
    }

    /// Compiles a component.
    ///
    /// # Errors
    ///
    /// As [`WasmBackend::compile`].
    pub fn compile(
        &self,
        wasm: &[u8],
        plugin_id: &str,
    ) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        self.inner.compile(wasm, plugin_id)
    }

    /// Instantiates a compiled component.
    ///
    /// # Errors
    ///
    /// As [`WasmBackend::instantiate`].
    pub fn instantiate(
        &self,
        compiled: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError> {
        self.inner.instantiate(self, compiled)
    }
}

impl fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Backend")
            .field("kind", &self.kind())
            .field("engine_version", &self.engine_version())
            .finish_non_exhaustive()
    }
}

/// An engine that compiles components and makes instances of them.
///
/// The `Any` supertrait is what makes [`Backend::concrete`] possible: a downcast needs a type id, and a type id is only
/// meaningful for a type that cannot have borrowed a caller's stack.
pub trait WasmBackend: Send + Sync + std::any::Any {
    /// Which engine this is.
    fn kind(&self) -> BackendKind;

    /// What this engine can enforce.
    fn enforcement(&self) -> Enforcement;

    /// The engine's version, which belongs in a compile cache key: a precompiled artefact is only loadable by the
    /// engine that produced it.
    fn engine_version(&self) -> &str;

    /// Compiles a component.
    ///
    /// # Errors
    ///
    /// [`BackendError::Compile`] when the artifact is not a component this engine understands, and
    /// [`BackendError::UnknownImport`] or [`BackendError::UngrantedImport`] when its imports are not ones the host
    /// provides for this plugin.
    fn compile(&self, wasm: &[u8], plugin_id: &str) -> Result<Box<dyn CompiledArtifact>, BackendError>;

    /// Precompiles, for an engine whose compiled form can be cached on disk.
    ///
    /// # Errors
    ///
    /// [`BackendError::BackendUnavailable`] when this engine has no such form, which
    /// [`Enforcement::precompile`] is what reports.
    fn precompile(&self, wasm: &[u8], plugin_id: &str) -> Result<Vec<u8>, BackendError> {
        let _ = (wasm, plugin_id);
        Err(BackendError::BackendUnavailable { kind: self.kind() })
    }

    /// Loads what [`WasmBackend::precompile`] produced.
    ///
    /// # Errors
    ///
    /// As [`WasmBackend::precompile`], plus [`BackendError::Compile`] for bytes this engine did not produce.
    fn load_precompiled(&self, bytes: &[u8], plugin_id: &str) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        let _ = (bytes, plugin_id);
        Err(BackendError::BackendUnavailable { kind: self.kind() })
    }

    /// Instantiates a compiled component.
    ///
    /// Instantiates a compiled component.
    ///
    /// `backend` is the handle this engine is reachable through, because an instance holds one: a plugin call later
    /// needs the engine's import table and its counters, and an instance that could only reach `&self` would need the
    /// caller of *every* call to hand the engine back.
    ///
    /// # Errors
    ///
    /// [`BackendError::Instantiate`] when the component's start function fails or a required export is missing.
    fn instantiate(
        &self,
        backend: &Backend,
        compiled: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError>;
}
