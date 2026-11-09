//! The plugins this kernel can ask, and how it asks them.
//!
//! # What this type is for
//!
//! The design document's flow (`07-core-kernel.md` §6.2) has nine steps, and steps 3 through 8 all require calling
//! code the kernel does not own: compile a component, hold an instance, run one entry point under a budget, and hand
//! back what it said. That machinery is [`synra_plugin_host`], and this file is the part of it the kernel actually needs —
//! without it the kernel can hold an [`crate::intent::Board`] and can never put a candidate into one.
//!
//! # Why the engine is handed in rather than built here
//!
//! Because `wasmtime` is a large dependency and this crate must not acquire it. The engine is a host decision: the
//! windowless daemon and the Tauri shell each build one, and they may legitimately differ. So [`PluginSet`] takes a
//! [`Backend`] in its constructor and every test uses [`synra_plugin_host::ScriptedBackend`], which is a backend with no
//! guest in it at all. That is what makes this file's tests possible without a `.wasm` anyone would have to review —
//! and a test that cannot run on a machine with no engine is a test that does not run.
//!
//! # Why loading compiles
//!
//! Because the artifact's imports are what the host is asked to provide, and finding an import the host cannot satisfy
//! at *call* time is a call that fails on a user's share. [`PluginSet::load`] compiles, so the import table is known
//! before any user-visible moment exists to fail in.
//!
//! # Why instances come from a pool rather than being made per call
//!
//! Instantiation is the expensive part of running a plugin, and a plugin that declares itself `stateful` would lose its
//! memory to a pool that hands out any instance. The pool is what makes both true at once, and its refusal is returned
//! rather than retried here: a plugin at its instance limit is a fact the caller reports, not a delay the kernel hides.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::Mutex;
use synra_capability::CapabilitySet;
use synra_plugin_host::{
    Backend, BackendError, CallBudget, CallOutcome, CompiledArtifact, Health, InstancePolicy,
    Lifecycle, PluginInstance, State, Transition,
};
use synra_protocol::ids::PluginId;

/// Guest execution and outcome handling.
mod execute;
/// Load, lifecycle and fault transitions.
mod lifecycle;
/// Plugin registry, metrics and audit storage.
mod state;
/// Shared plugin vocabulary and internal state.
mod types;

pub use state::*;
use types::{Authority, Loaded};
pub use types::{PluginSetError, PluginSpec};

#[cfg(test)]
mod tests;
