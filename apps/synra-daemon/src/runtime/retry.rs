//! Sending again the dispatches a restart left in flight.
//!
//! # Why the daemon needs this
//!
//! Because the window has had it since the board was made durable, and the daemon had not: it restored every intent and
//! then left a `Dispatching` one exactly as it found it. The peer is still waiting on an answer, the board says the action
//! is running, and the one process that could ask again does nothing until the 24-hour expiry. The request identifier is
//! the receiving side's idempotency key, so asking again is safe: it either runs the action once or returns the outcome
//! that already happened.
//!
//! # What this is
//!
//! One pass at start-up, not the shell's backoff loop. The schedule and its persistence belong to the host with a window
//! and a page that shows it; this host's job is to not forget the request. A later round can give the daemon the same
//! queue — until then the honest description is "one attempt, made when the daemon starts".
//!
//! # Why it takes pieces rather than a `Runtime`
//!
//! Because the runtime is owned by the serving thread and cannot be shared; the host, the board and the database are
//! already behind `Arc`s, and those are the only parts a resend touches.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_core::Host;
use synra_core::dispatch::orchestrate;
use synra_core::intent::{Board, persist};
use synra_protocol::ids::{DeviceId, IntentId};
use synra_store::SynraDb;

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Dispatches this pass tried to send again.
    pub(crate) attempted: usize,
    /// Dispatches whose answer arrived and was applied.
    pub(crate) answered: usize,
    /// Dispatches that were sent and answered with nothing inside the wait.
    pub(crate) unanswered: usize,
    /// Dispatches whose send could not be made at all.
    pub(crate) failed: usize,
}

/// Sends every dispatch this device left in flight, once.
pub(crate) fn resend_outstanding(
    host: &Arc<Mutex<Host>>,
    board: &Arc<Mutex<Board>>,
    db: &Arc<Mutex<SynraDb>>,
    local: DeviceId,
) -> Report {
    let now = synra_store::sqlite::now_ms();
    // The board is read once, and the lock released before the first dial: a send blocks for up to the whole wait, and a
    // board guard held across it would make every intent command wait for the network.
    let pending: Vec<_> = board
        .lock()
        .all()
        .into_iter()
        .filter_map(|intent| orchestrate::resume(intent, local, now))
        .collect();

    let mut report = Report::default();
    for outbound in pending {
        report.attempted += 1;
        match super::commands::exchange(host, &outbound, true) {
            Ok(Some(reply)) => match orchestrate::apply_result(board, &reply) {
                Ok(Some(id)) => {
                    checkpoint(board, db, id);
                    report.answered += 1;
                }
                // A reply this device is not waiting on: the intent may have been cancelled while the answer was in
                // flight. Nothing to apply.
                Ok(None) => report.unanswered += 1,
                Err(error) => {
                    eprintln!("synra-daemon: the result could not be applied: {error}");
                    report.failed += 1;
                }
            },
            Ok(None) => report.unanswered += 1,
            Err(error) => {
                eprintln!("synra-daemon: {} could not be sent again: {error}", outbound.to);
                report.failed += 1;
            }
        }
    }
    report
}

/// Writes the intent's new state down.
///
/// The command path does this through `Runtime::checkpoint_intent`; a free function cannot, and the mapping it uses is the
/// kernel's (`persist::record_of`), so there is still one description of a row.
fn checkpoint(board: &Arc<Mutex<Board>>, db: &Arc<Mutex<SynraDb>>, id: IntentId) {
    let record = {
        let board = board.lock();
        persist::record_of(&board, id, synra_store::sqlite::now_ms())
    };
    let Some(record) = record else {
        return;
    };
    if let Err(error) = db.lock().save_intent(&record) {
        // The action has already happened, so this is a record a restart will not have — not a failure of the resend.
        eprintln!("synra-daemon: intent {id} was not written down: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_core::intent::{Choice, IntentSource, IntentState};
    use synra_protocol::ids::{PluginId, RequestId};

    #[test]
    fn a_dispatch_with_no_known_address_is_counted_and_left_alone() {
        // ★ The pass must not invent an address, and must not change the intent when it cannot send: "I could not reach
        // it" is not "it failed", and the 24-hour expiry or a late answer still owns the outcome.
        let dir = std::env::temp_dir().join(format!("synra-daemon-retry-{}", RequestId::new()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let runtime = crate::runtime::tests::runtime(&dir);
        let peer = DeviceId::new();
        let now = synra_store::sqlite::now_ms();
        let (id, ..) = runtime.board.lock().raise(
            IntentSource::Direct {
                plugin_id: PluginId::parse("@acme/opener").expect("a plugin id"),
                action: "open".to_owned(),
                params: serde_json::json!({}),
                target: peer,
            },
            Choice::Automatic,
            None,
            Some(RequestId::new()),
            now,
        );

        let report = resend_outstanding(
            &runtime.host,
            &runtime.board,
            &runtime.db,
            runtime.identity.device_id,
        );

        assert_eq!(report.attempted, 1);
        assert_eq!(report.failed, 1, "there is no address to dial");
        assert!(matches!(
            runtime.board.lock().get(id).map(|intent| intent.state.clone()),
            Some(IntentState::Dispatching { .. })
        ));
        drop(runtime);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
