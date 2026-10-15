//! Running the action the user confirmed.
//!
//! # Why this is separate from [`super::matching`]
//!
//! Because the two do opposite things, and the difference is the point. `can-handle` runs for **every** plugin the router
//! asks, before the user has chosen anything, and the contract says it has no side effects — a plugin that opened a
//! browser there would have done it for every share the user then cancelled. `execute` runs **once**, for the plugin the
//! user picked, and its whole purpose is the side effect.
//!
//! Keeping them in one module would put "ask everyone, harmlessly" and "run the chosen one, for real" behind one name,
//! and the next person to add a call would have to work out which they were writing.

use synra_plugin_host::{CallBudget, CallOutcome, Work};
use synra_protocol::ids::PluginId;

use crate::intent::IntentCandidate;

use super::plugins::{PluginSet, PluginSetError};

/// The budget one `share.execute` call gets.
///
/// # Why this is not [`super::CAN_HANDLE_BUDGET_MS`]
///
/// Because they answer different questions. `can-handle` decides whether a prompt appears while the user is still looking
/// at what they shared, so it is measured in tens of milliseconds. `execute` performs the action the user asked for —
/// opening a link, writing a file, reaching a device — and a few seconds is ordinary for that. Reusing the matching
/// budget would abort actions that were working, and reusing this one for matching would let one slow plugin hold a
/// prompt for five seconds.
pub const EXECUTE_BUDGET_MS: u64 = 5_000;

/// The budget a confirmed action runs under.
#[must_use]
pub const fn execute_budget() -> CallBudget {
    CallBudget {
        fuel: None,
        timeout: Some(std::time::Duration::from_millis(EXECUTE_BUDGET_MS)),
        max_memory_growth: None,
    }
}

/// Runs the action a candidate proposed.
///
/// # Why the arguments are serialised here rather than passed through
///
/// Because the candidate's `args` is a [`serde_json::Value`] the plugin produced during matching, and the contract's
/// `execute` takes a JSON string. `to_string` on a value cannot produce invalid JSON, so the only failure here is the
/// plugin's own, and there is nothing for a caller to check.
///
/// # Errors
///
/// [`PluginSetError`] when the plugin is not loaded, is at its instance limit, or the call cannot be made. A plugin that
/// ran and returned a failure is **not** an error here: it is an outcome, and the caller records it as one.
pub fn execute(
    set: &mut PluginSet,
    plugin_id: &PluginId,
    candidate: &IntentCandidate,
    now_ms: u64,
) -> Result<CallOutcome, PluginSetError> {
    let work = Work::Execute {
        action: candidate.planned.action.clone(),
        args_json: candidate.planned.args.to_string(),
    };
    set.call(plugin_id, &work, execute_budget(), now_ms)
}
