//! The plugin sandbox: what a plugin may do, how much of it, and what state it is in.
//!
//! # Three questions, and this crate is where they are answered
//!
//! A plugin is code from a stranger that runs inside the user's application and can talk to the user's other
//! devices. Three separate mechanisms keep that from being a mistake, and they fail in different ways:
//!
//! * **Capability gates** — *what* a plugin may do. The DSL, the matching and the three-layer enforcement live in
//!   [`synra_capability`] and [`synra_plugin_api`], because they are contracts a plugin author has to be held to and
//!   a contract belongs where it can be read without the host. This crate holds the host-side decision: whether a
//!   *specific call*, with all its arguments, is one the plugin was granted.
//! * **Quotas** ([`quota`]) — *how much*. Static limits and rate limits need different answers: one is a refusal with
//!   no retry, the other says when to try again. The escalation ladder is here because "this plugin is asking too
//!   often" has to become visible before it becomes a plugin that is disabled.
//! * **Lifecycle** ([`lifecycle`]) — *what it is currently doing*. The state machine's value is in the transitions it
//!   refuses: a plugin may not run before its grants are decided, may not be reactivated while faulted, and may not be
//!   uninstalled while running.
//!
//! # What is here
//!
//! * **The engine** ([`engine`]) — the backend trait, the real `wasmtime` backend behind the `wasm-runtime` feature,
//!   the thread pool a blocking engine needs so it cannot stall an asynchronous runtime, the per-call budget
//!   (`fuel` + wall clock + memory), and the compile cache whose key names every input that changes the bytes.
//! * [`host_surface`] — the generated table of host functions and the gate each needs, so a contract change that is
//!   not reflected here is a build failure rather than a host call nobody checks.
//! * [`quota`] — *how much*: static limits and rate limits, which fail differently, plus the escalation ladder that
//!   turns "asking too often" into a visible degradation before it becomes a disabled plugin.
//! * [`lifecycle`] — *what it is currently doing*: the state machine whose value is the transitions it refuses.
//!
//! # A build without the engine
//!
//! `wasm-runtime` is off by default, and this crate then compiles no engine at all. That is not a stub: it is the
//! configuration in which the execution layer is *testable*, because [`engine::scripted`] answers from a table instead
//! of running a guest, and the questions that get answered wrongly here — which instance a call gets, whether a
//! deadline was armed, what a run of traps does to health — do not need a guest to be asked.
//!
//! [`engine::Enforcement`] is how a caller learns the difference. A backend reports what it can actually do, and a
//! host about to run third-party code refuses a limit it cannot enforce rather than believing it has one.
//!
//! # The pool's one hard rule
//!
//! A plugin that declares itself `stateful` keeps memory between calls, so its instances are **not**
//! interchangeable. Round-robin would silently lose its state, and the symptom would be a plugin that works when only
//! one thing is happening — which is the hardest kind of bug to be told about.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod engine;
pub mod host_surface;
pub mod lifecycle;
pub mod pool;
pub mod quota;
pub mod registry;
pub mod verify;

pub use registry::{
    DEFAULT_REGISTRY, Dist, FetchFailure, Integrity, MAX_PACKUMENT_BYTES, MAX_VERSIONS, PackagePattern, Packument,
    RegistryConfig, RegistryMirror, SizeBlock, SynraBlock, VersionEntry, check_integrity, compare_versions,
};
pub use verify::{
    Candidate, HostFacts, Report as VerifyReport, Stage, Step, Verdict as VerifyVerdict, VerifyError, find_cycle,
    host_world, verify as verify_package,
};

pub use engine::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, CompileCache, Enforcement, Epoch,
    EpochTicker, ExecutorRefusal, HostKind, PluginInstance, Scripted, ScriptedBackend, WasmBackend, WasmExecutor, Work,
};
pub use host_surface::{
    HostGate, CAPABILITIES, EXPORTED_INTERFACES, HOST_FUNCTIONS, HOST_INTERFACE, PACKAGE, PACKAGE_VERSION,
    gate, gated, is_declared_capability, permits, provided, provides, required_capabilities, undeclared_imports,
    ungated,
};
pub use lifecycle::{
    Consent, FailStage, Failed, InstallSource, Lifecycle, Move, MoveError, PluginSlot, Progress, Resolved, State,
    StopRecord, Transition, TransitionError, UNSTABLE_THRESHOLD, Verified,
};
pub use pool::{
    IDLE_EVICT_AFTER, InstancePolicy, InstancePool, InstanceRecord, PoolRefusal, PoolReport,
    RECYCLE_AFTER_CALLS,
};
pub use quota::{
    Budget, DEGRADE_AFTER_WINDOWS, FAULT_AFTER_WINDOWS, Health, PERSISTENCE_WINDOW,
    PERSISTENT_REFUSALS, Quota, QuotaReport, RateKind, RateLimited, StaticRefusal, TokenBucket,
};
