//! Scripted compiled artifacts and plugin instances.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::super::types::{BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, PluginInstance, Work};
use super::types::{Scripted, raise};
use super::backend::Shared;

/// A compiled artefact this backend made.
#[derive(Debug)]
pub struct ScriptedArtifact {
    pub(super) digest: String,
    pub(super) plugin_id: String,
    /// What this artifact claims to import, for the kernel's load-time coverage check.
    pub(super) imports: Vec<String>,
}

impl CompiledArtifact for ScriptedArtifact {
    fn kind(&self) -> BackendKind {
        BackendKind::Scripted
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn imports(&self) -> &[String] {
        &self.imports
    }
}

/// An instance of a scripted component.
#[derive(Debug)]
pub struct ScriptedInstance {
    pub(super) shared: Arc<Shared>,
    pub(super) memory: u64,
    pub(super) host_calls: u64,
    /// The epoch of the most recent call's deadline, which is what a test reads to prove one was armed.
    pub(super) deadline_epoch: Option<u64>,
    /// Which plugin this instance belongs to, so per-plugin scripts are found.
    pub(super) plugin_id: String,
}

impl PluginInstance for ScriptedInstance {
    fn kind(&self) -> BackendKind {
        BackendKind::Scripted
    }

    fn memory_bytes(&self) -> u64 {
        self.memory
    }

    fn host_calls(&self) -> u64 {
        self.host_calls
    }

    fn deadline_epoch(&self) -> Option<u64> {
        self.deadline_epoch
    }

    fn call(&mut self, work: &Work, budget: CallBudget) -> Result<CallOutcome, BackendError> {
        let _ = self.shared.calls.fetch_add(1, Ordering::AcqRel);
        self.host_calls = self.host_calls.saturating_add(1);
        // A token amount of memory, so a test that watches growth sees something move rather than a constant zero that
        // would also satisfy an untouched instance.
        self.memory = self.memory.saturating_add(4096);

        Ok(match self.shared.answer_for(&self.plugin_id, work) {
            Scripted::Ok(payload) => CallOutcome::Ok(payload),
            Scripted::Failed {
                code,
                message,
                details,
            } => CallOutcome::Failed {
                code,
                message,
                details,
            },
            Scripted::Trap { detail } => CallOutcome::Trap { detail },
            // ★ A panic in the host, which is a different failure from a trap the *guest* produced.
            //
            // A `Trap` is the engine reporting that the guest broke a rule, and it arrives here as an ordinary
            // `CallOutcome`. This one unwinds. It exists so the boundary in `synra-core`'s `PluginSet::run_on` — the
            // `catch_unwind` that `[profile.release] panic = "unwind"` is configured for — can be tested at all: before
            // this variant there was no way to raise a panic from behind the `WasmBackend` trait, so the claim that a
            // plugin cannot take the kernel down with it had nothing behind it.
            Scripted::Panic { message } => raise(&message),
            // Both of these are the *budget* being reported, so a call that asked for no limit cannot produce them:
            // a script that ignored that would let a test assert a timeout on a call the host never bounded.
            Scripted::Timeout => match budget.timeout {
                Some(after) => CallOutcome::Timeout { after },
                None => CallOutcome::Ok(String::new()),
            },
            Scripted::FuelExhausted => match budget.fuel {
                Some(fuel) => CallOutcome::FuelExhausted { fuel },
                None => CallOutcome::Ok(String::new()),
            },
            Scripted::MemoryExceeded => match budget.max_memory_growth {
                Some(limit) => CallOutcome::MemoryExceeded { limit },
                None => CallOutcome::Ok(String::new()),
            },
        })
    }
}




