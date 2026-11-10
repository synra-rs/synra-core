use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use synra_protocol::envelope::Envelope;

use crate::host::Host;
use crate::late_queue::LateQueue;
use crate::link::PeerLink;

use super::late::deliver_late;
use super::{KernelEventCallback, KernelEventOutcome};

/// Answers one kernel event on the connection it arrived on.
///
/// # Why this is a function rather than an arm
///
/// Because the connection loop is long enough that adding four outcomes to one of its arms pushed it past the complexity
/// budget — and the budget is right: a reader of the loop should see "an intent event is answered here", not four branches
/// about what kind of answer it was.
pub(super) fn answer_kernel_event(
    host: &Arc<Mutex<Host>>,
    link: &mut PeerLink,
    envelope: &Envelope,
    on_kernel_events: &Arc<KernelEventCallback>,
    events: &mut Vec<String>,
    data_dir: &Path,
) {
    let event = envelope.event.as_str();
    let caller = link.peer();
    let outcome = if envelope.from != caller {
        KernelEventOutcome::Refused("the event names a device this connection is not".to_owned())
    } else {
        on_kernel_events(envelope, &caller)
    };
    match outcome {
        KernelEventOutcome::Handled => events.push(format!("handled {event}")),
        KernelEventOutcome::Receipt(receipt) => match link.send(&receipt) {
            Ok(()) => events.push(format!("receipt sent {event}")),
            Err(error) => events.push(format!("receipt failed {event}: {error}")),
        },
        KernelEventOutcome::Reply(reply) => {
            events.push(format!("answered {event}"));
            if let Err(error) = link.send(&reply) {
                // ★ The asker stopped waiting and closed the connection. The answer is not lost: the device it is addressed
                // to has a listener, and a result that arrives after the wait is still the outcome of an action that really
                // ran. Dialling back is what turns "dispatching for ever" into "the next snapshot is right".
                eprintln!(
                    "synra-daemon: the answer to {event} could not be sent on the asking link ({error}); delivering it to {} instead",
                    reply.target
                );
                if let Err(error) = deliver_late(host, &reply) {
                    // ★ And when the dial-back fails as well, the answer is written down rather than dropped: the host's
                    // periodic task drains this queue. A file that cannot be written is reported and the connection still
                    // continues — the work it describes really happened.
                    match LateQueue::in_data_dir(data_dir)
                        .push(&reply, synra_store::sqlite::now_ms())
                    {
                        Ok(()) => {
                            host.lock().count_late_delivery("queued");
                            eprintln!(
                                "synra-daemon: the answer to {event} for {} is queued for a later attempt ({error})",
                                reply.target
                            );
                        }
                        Err(queue_error) => eprintln!(
                            "synra-daemon: the answer to {event} for {} could not be delivered ({error}) or queued ({queue_error})",
                            reply.target
                        ),
                    }
                }
            }
        }
        KernelEventOutcome::Refused(why) => {
            eprintln!("synra-daemon: {event} could not be handled: {why}");
        }
        // Not an error: an event this kernel does not run is one it must not guess at.
        KernelEventOutcome::Ignored => events.push(format!("unhandled {event}")),
    }
}
