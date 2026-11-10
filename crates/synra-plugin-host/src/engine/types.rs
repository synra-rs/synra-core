//! What a plugin call *is*, and what it can come back as.
//!
//! # Why this vocabulary is separate from any engine
//!
//! Because the two questions this crate answers — may this call happen, and how much of it may happen — are answered
//! before an engine exists. An execution layer written against `wasmtime` types would make every one of those answers
//! untestable in an environment where the engine does not build, and those are precisely the answers that get got
//! wrong. The engine sits behind [`WasmBackend`], and everything here is the shape of the conversation with it.

mod backend;
mod enforcement;
mod outcome;
mod traits;
mod work;

pub use backend::Backend;
pub use enforcement::Enforcement;
pub use outcome::{BackendError, CallBudget, CallOutcome};
pub use backend::WasmBackend;
pub use traits::{CompiledArtifact, PluginInstance};
pub use work::{BackendKind, HostKind, Work};
