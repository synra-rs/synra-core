//! Running a plugin: the engine, the threads it runs on, and what it may use while it runs.
//!
//! # The four things this layer decides
//!
//! | Question | Answered by |
//! | --- | --- |
//! | What can this engine do to a runaway guest? | [`types::Enforcement`], reported by the backend |
//! | Where does a call run? | [`executor::WasmExecutor`], on threads of its own |
//! | How much may one call use? | [`types::CallBudget`], taken from the plugin's quota |
//! | Is the compiled form worth keeping? | [`cache::CompileCache`], keyed on everything that changes the bytes |
//!
//! # Why the engine is behind a trait
//!
//! Two reasons, and the second is the one that matters:
//!
//! * backends trade compile time, run time and binary size against each other, and which is right depends on the
//!   target — a phone wants a baseline compiler, a machine that cannot JIT wants an interpreter;
//! * the questions this crate gets **wrong** — which instance a call gets, whether a deadline was armed, what a run of
//!   traps does to health — are not questions an engine answers. Putting them behind a trait makes them testable
//!   without a guest, which is what [`scripted`] is for.
//!
//! A backend that cannot enforce a limit a caller asks for says so through
//! [`Enforcement::first_gap`](types::Enforcement::first_gap), and the caller refuses rather than running third-party
//! code with a bound it does not have.

pub mod cache;
pub mod executor;
pub mod scripted;
pub mod types;

#[cfg(feature = "wasm-runtime")]
pub mod linker;
#[cfg(feature = "wasm-runtime")]
mod wasmtime_backend;

pub use cache::{CACHED_EXTENSION, CacheEntry, CacheError, CacheKey, CompileCache};
pub use executor::{
    EPOCH_PERIOD, Epoch, EpochTicker, ExecutorRefusal, MAX_THREADS, ThreadPool, WasmExecutor,
};
pub use scripted::{ScriptError, Scripted, ScriptedArtifact, ScriptedBackend, ScriptedInstance, digest_of};
pub use types::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, Enforcement, HostKind,
    PluginInstance, WasmBackend, Work,
};

#[cfg(feature = "wasm-runtime")]
// ★ `EngineArtifact` is re-exported rather than left to `wasmtime_backend`'s own module because its `imports` and
// `exports` read the component's own type rather than a manifest — which is the difference between a claim and a fact,
// and is what an import check has to be built on. Reachable is the difference between that being available and being
// written twice.
pub use wasmtime_backend::{EngineArtifact, WasmtimeBackend, shared};
