//! The action a thread is currently working on, for code that was not handed its trace.
//!
//! # Why a thread-local rather than a parameter
//!
//! Because the code that needs this is a **host function called by a guest**: a plugin's `log` reaches the host with a
//! plugin, a level and a message, and no place for an action identifier — the contract is the plugin's, and adding a trace
//! argument to every host function would make the action a plugin's responsibility to report. The thread that runs the
//! guest call does know the trace, because [`PluginSet::call_traced`](synra_core) is the funnel every action goes
//! through; a thread-local is how it tells the host functions it calls.
//!
//! # Why a guard rather than set-and-clear
//!
//! Because the scope has to be restored even when the guest traps: `run_on` catches the panic, but a `set(None)` after the
//! call would be skipped by an early return. The guard's `Drop` also restores the **previous** value, so a nested call (a
//! host function that calls back into the kernel) does not erase the outer action.

use std::cell::Cell;

use synra_protocol::ids::TraceId;

thread_local! {
    /// The trace of the action this thread is running, if any.
    static CURRENT: Cell<Option<TraceId>> = const { Cell::new(None) };
}

/// The trace of the action running on this thread, when there is one.
///
/// A matching pass and a lifecycle tick have none: they are not part of a user action, and answering `None` is what keeps
/// their log lines from being attributed to somebody else's share.
#[must_use]
pub fn current() -> Option<TraceId> {
    CURRENT.with(Cell::get)
}

/// Makes `trace` current until the returned guard is dropped, then restores what was current before.
///
/// `None` still creates a scope, so a call that has no action clears the value for its duration and restores the outer one
/// afterwards — which is what a nested call from inside an action needs.
#[must_use = "the trace is only current while the guard lives"]
pub fn enter(trace: Option<TraceId>) -> Guard {
    let previous = CURRENT.with(|current| current.replace(trace));
    Guard(previous)
}

/// Restores the trace that was current when its scope began.
#[derive(Debug)]
pub struct Guard(Option<TraceId>);

impl Drop for Guard {
    fn drop(&mut self) {
        CURRENT.with(|current| current.set(self.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_starts_with_no_action() {
        assert_eq!(current(), None);
    }

    #[test]
    fn a_scope_is_current_until_it_ends() {
        let trace = TraceId::new();
        {
            let _scope = enter(Some(trace));
            assert_eq!(current(), Some(trace));
        }
        assert_eq!(current(), None, "the guard restores what was there before");
    }

    #[test]
    fn a_nested_scope_restores_the_outer_one() {
        // ★ A host function that calls back into the kernel would otherwise erase the action it was called for: the
        // outer line would lose its trace at exactly the point the call became interesting.
        let outer = TraceId::new();
        let inner = TraceId::new();
        let _outer = enter(Some(outer));
        {
            let _inner = enter(Some(inner));
            assert_eq!(current(), Some(inner));
        }
        assert_eq!(current(), Some(outer));
    }

    #[test]
    fn a_scope_with_no_action_clears_it_for_its_duration() {
        let outer = TraceId::new();
        let _outer = enter(Some(outer));
        {
            let _none = enter(None);
            assert_eq!(current(), None);
        }
        assert_eq!(current(), Some(outer));
    }
}
