//! Routing, as this host reaches it.
//!
//! # Why this is a shim rather than the implementation
//!
//! Because the orchestration used to live here — **inside a binary** — and a second host needs it. The desktop shell has
//! its own `Board` and its own four intent commands, and it could not reuse a line of what was in this file; it would have
//! had to duplicate it. It lives in [`synra_core::dispatch::orchestrate`] now, where both hosts reach it, and what remains
//! here is the translation: the library answers with a [`RouteError`] carrying a contract code, and the control protocol
//! answers with a `Refusal` carrying the same code and a sentence.
//!//! The tests drive the orchestration through this host's own entry points.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_control::Refusal;
use synra_core::dispatch::orchestrate::{self, RouteError};
use synra_core::dispatch::PluginSet;
use synra_core::intent::Board;
use synra_protocol::inbound::ShareItem;

/// Everything an inbound share is routed with.
pub use synra_core::dispatch::orchestrate::Router;

/// Answers one kernel event that arrived on a link.
///
/// # Why this is a function rather than a closure in `serve`
///
/// Because these three arms are the daemon's behaviour for a peer's message, and a test should call the code `serve` runs
/// rather than a re-description of it. The closure in `serve` supplies the board, the plugins and this device; everything
/// that decides *what happens* is here.
///
/// # The three events
///
/// * `INTENT_INVOKE` runs the action here and answers with `INTENT_RESULT`.
/// * `INTENT_CANCEL` stops work this device has not finished.
/// * `INTENT_RESULT` is the **late** answer to an action this device dispatched: the sender gave up waiting, the receiver
///   finished anyway, and dialled back. `apply_result` matches it by `reply_to` and sender, and ignores one for work that
///   is no longer in flight.
pub(crate) fn handle_event(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    local_device: synra_protocol::ids::DeviceId,
    envelope: &synra_protocol::envelope::Envelope,
    now_ms: i64,
) -> synra_core::listener::KernelEventOutcome {
    use synra_core::listener::KernelEventOutcome;
    use synra_protocol::event::events;

    match envelope.event.as_str() {
        events::INTENT_INVOKE => {
            match orchestrate::accept_remote(plugins, board, local_device, envelope, now_ms) {
                Ok(Some(reply)) => KernelEventOutcome::Reply(Box::new(reply)),
                // The same request twice with the first copy still running: the first copy answers.
                Ok(None) => KernelEventOutcome::Handled,
                Err(error) => KernelEventOutcome::Refused(error.to_string()),
            }
        }
        events::INTENT_CANCEL => match orchestrate::accept_cancel(board, envelope) {
            Ok(_) => KernelEventOutcome::Handled,
            Err(error) => KernelEventOutcome::Refused(error.to_string()),
        },
        events::INTENT_RESULT => match orchestrate::apply_result(board, envelope) {
            Ok(applied) => {
                // ★ The late step joins the trace too: a user following an action with `synra logs --trace` should see the
                // answer arrive on the second connection, not just the first one's timeout.
                if let Some(id) = applied {
                    tracing::info!(
                        trace_id = %envelope.trace_id,
                        intent = %id,
                        "late outcome applied"
                    );
                }
                // An answer for work this device is not waiting on is not an error: a late duplicate, or a result whose
                // intent was cancelled while the answer was in flight. `apply_result` returns `Ok(None)` and says so.
                KernelEventOutcome::Handled
            }
            Err(error) => KernelEventOutcome::Refused(error.to_string()),
        },
        _ => KernelEventOutcome::Ignored,
    }
}

/// A library failure as this host reports it.
///
/// One line, and that is the point of the library carrying the contract's own codes: a host that had to map a bespoke
/// enum would be inventing the vocabulary back.
fn as_refusal(error: RouteError) -> Refusal {
    Refusal::new(error.code, error.message)
}

/// Routes a share and reports what the plugins said.
///
/// # Errors
///
/// [`Refusal`] when the item cannot be serialised into the shape a plugin is asked about.
pub(super) fn dispatch(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    item: &ShareItem,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    orchestrate::dispatch(plugins, board, item, now_ms).map(|answer| answer.to_json()).map_err(as_refusal)
}

/// Reads an intent's current state and candidates.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten.
pub(super) fn snapshot(board: &Arc<Mutex<Board>>, intent: &str) -> Result<serde_json::Value, Refusal> {
    orchestrate::snapshot(board, intent).map(|answer| answer.to_json()).map_err(as_refusal)
}

/// Applies the user's answer, and runs what they chose.
///
/// # Errors
///
/// [`Refusal`] when the intent is unknown or is not in a state that can be decided, when the named plugin was not among
/// the candidates, or when the identifier is not one.
pub(super) fn decide(
    plugins: &Arc<Mutex<PluginSet>>,
    board: &Arc<Mutex<Board>>,
    local_device: synra_protocol::ids::DeviceId,
    intent: &str,
    plugin_id: Option<&str>,
    target: Option<&str>,
    now_ms: i64,
) -> Result<orchestrate::Decided, Refusal> {
    // ★ The typed answer, not its JSON.
    //
    // This rendered to `serde_json::Value` like its neighbours, and that was fine while a decision could only run here:
    // the answer was the whole outcome. It is not fine now — a remote decision's outcome is an **envelope the host has to
    // send**, and rendering it to JSON threw the envelope away one line before anything could put it on a link. The
    // caller renders it for the wire after it has used what only the type carries.
    orchestrate::decide(plugins, board, local_device, intent, plugin_id, target, now_ms)
        .map_err(as_refusal)
}

/// Abandons an intent.
///
/// # Errors
///
/// [`Refusal`] when the identifier is not one or names an intent this kernel never raised.
pub(super) fn cancel(
    board: &Arc<Mutex<Board>>,
    local_device: synra_protocol::ids::DeviceId,
    intent: &str,
    reason: &str,
) -> Result<orchestrate::StateChange, Refusal> {
    // Typed rather than rendered, for the reason `decide` is: a cancellation of a *dispatched* intent carries an envelope
    // the host has to send, and rendering it here threw that away — the same mistake, in the same place, one round later.
    orchestrate::cancel(board, local_device, intent, reason).map_err(as_refusal)
}


#[cfg(test)]
mod tests;
