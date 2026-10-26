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

/// Refuses an engine that cannot enforce the limits this host will ask for.
///
/// # Why this is the caller `first_gap` was written for, and why it is here
///
/// See [`BackendError::CannotEnforce`](types::BackendError::CannotEnforce) for the decision and for why it is not per call.
/// The short version: an engine missing a limit is a fact about the installation, so it is asked once, at the only moment a
/// person can act on it.
///
/// # Errors
///
/// [`BackendError::CannotEnforce`](types::BackendError::CannotEnforce) naming the first limit the engine cannot honour.
pub fn check_enforceable(
    backend: &Backend,
    quota: &crate::quota::Quota,
) -> Result<(), BackendError> {
    match backend.enforcement().first_gap(&CallBudget::from_quota(quota)) {
        Some(missing) => Err(BackendError::CannotEnforce { missing }),
        None => Ok(()),
    }
}

/// The largest component this host will compile.
///
/// ★ Why this lives here rather than beside the engine that enforces it.
///
/// It is a **policy** number, not an engine detail: the CLI checks it when an author runs `verify`, and the host checks it
/// before wasmtime sees any bytes. It was defined inside `wasmtime_backend`, which is behind the `wasm-runtime` feature — so
/// `tools/synra-plugin-cli`, which does not enable that feature and should not have to, could not reach it and kept a
/// second literal with the same value.
///
/// Two literals that agree is a coincidence with a lifetime. What it costs when they diverge: `verify` passes an artifact
/// the host then refuses at load, so a check told an author their plugin was fine and the kernel disagreed.
///
/// Sixteen mebibytes, matching what the tooling has always accepted. Wasmtime's own parser is not a resource limiter, so
/// this is the only thing standing between a hostile or broken artifact and the compiler.
pub const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

pub mod cache;
pub mod executor;
pub mod scripted;
pub mod session;
pub mod types;

#[cfg(feature = "wasm-runtime")]
pub mod linker;
#[cfg(feature = "wasm-runtime")]
mod wasmtime_backend;

#[cfg(all(test, feature = "wasm-runtime"))]
mod test_component;

pub use cache::{CACHED_EXTENSION, CacheEntry, CacheError, CacheKey, CompileCache};
pub use executor::{
    EPOCH_PERIOD, Epoch, EpochTicker, ExecutorRefusal, MAX_THREADS, ThreadPool, WasmExecutor,
};
pub use scripted::{ScriptError, Scripted, ScriptedArtifact, ScriptedBackend, ScriptedInstance, digest_of};
pub use session::LinkerSession;
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
