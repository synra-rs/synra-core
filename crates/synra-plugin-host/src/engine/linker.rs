//! The generated WIT host interface, backed by the shared permission and quota gate.
//!
//! Generated bindings own component signatures. The adapter translates their typed values into the
//! host-call dispatcher and returns structured WIT outcomes; it never flattens variants into tuples.

#![cfg(feature = "wasm-runtime")]

use super::session::LinkerSession;
use super::wasmtime_backend::{StoreData, bindings};
use crate::host_calls::{CallError, HostCalls};
use crate::host_surface;
use wasmtime::component::{HasSelf, Linker};

mod host;

fn run(state: &mut StoreData, import_name: &str, argument: &str) -> Answer {
    state.host_calls = state.host_calls.saturating_add(1);
    let Some(session) = state
        .session
        .as_ref()
        .and_then(|held| held.downcast_ref::<LinkerSession>())
    else {
        // ★ No session means no plugin: a host function called by an instance the host did not hand a session to is
        // refused rather than run ungated. This is the only way to reach a definition without a gate, and it answers
        // with a refusal — which is why the invariant holds even here.
        return Answer::Denied(CallError::new(
            CallError::HOST_FAILED,
            "this instance has no plugin session, so the call cannot be authorised",
        ));
    };
    // The audit lock is held across the call rather than around the record, because a record has to be written even
    // when the call does nothing: the entry is what says the plugin asked.
    let mut audit = session.audit.lock();
    // ★ The purity rule, read off the store rather than assumed.
    //
    // `Work::allows_side_effects` answers whether the call now running may act, and the backend records the answer before
    // it dispatches. Without this the field existed and nothing read it, which is the same as not having it: a plugin's
    // `can-handle` could send, write, open and fetch to its grants' content, for every share the user then cancelled.
    let mut calls = HostCalls::new(
        session.host.as_ref(),
        session.plugin.clone(),
        &session.grants,
        &session.budget,
        &mut audit,
    );
    if !state.side_effects {
        calls = calls.pure();
    }
    // The gate's counters, when the session was given somewhere to put them.
    if let Some(metrics) = session.metrics.as_deref() {
        calls = calls.with_metrics(metrics);
    }
    let answer = match calls.call(import_name, argument) {
        Ok(answer) => Answer::Ok(answer),
        Err(error) => Answer::Denied(error),
    };
    // Both are released here rather than at the end of the function: the answer is a value the caller will render, and
    // a session lock held while that happens is a lock the next host call of the *same* guest would wait on.
    drop(calls);
    drop(audit);
    answer
}

enum Answer {
    Ok(String),
    Denied(CallError),
}

/// Registers the exact host interface generated from the production WIT contract.
pub(crate) fn define(linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
    bindings::Plugin::add_to_linker::<StoreData, HasSelf<StoreData>>(linker, |state| state)
}

fn import_name(function: &str) -> String {
    format!(
        "{}/{}#{function}",
        host_surface::PACKAGE,
        host_surface::HOST_INTERFACE
    )
}

#[cfg(test)]
#[path = "linker_tests.rs"]
mod tests;
