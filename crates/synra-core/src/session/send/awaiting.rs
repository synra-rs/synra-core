//! Waiting for confirmation, sending a whole file, and describing a digest.

use std::path::Path;

use synra_protocol::ids::TransferId;
use synra_protocol::session::SriDigest;

use crate::link::{Inbound, LinkError, PeerLink};
use crate::transfer::TransferSender;

use super::blocks::{propose, send_blocks};
use super::transfer::complete;
use super::super::types::{SessionError, SessionEvent};
use super::super::wire::{Message, classify, payload_of};
use synra_protocol::ids::TraceId;
use synra_protocol::session::{TransferAbort, TransferComplete, TransferProgress};

/// Waits for the receiver's confirmation that the object verified.
///
/// # Why the sender must wait, and what happened when it did not
///
/// Because the flow is `complete → complete`, and the second one is the **only** thing that says the file arrived. A sender
/// that sent its completion and returned would report success on its own say-so — and an end-to-end test caught exactly
/// that: the file landed byte-for-byte, the receiver confirmed it, and the sender had already stopped listening and timed
/// out. The transfer *was* complete; the sender simply never heard so.
///
/// Everything read on the way is skipped rather than refused: a receiver sends progress reports throughout, and the last
/// of them may be in flight when the completion goes out.
///
/// # Errors
///
/// [`SessionError::Link`] for a link failure, and [`SessionError::Payload`] for a malformed message. A peer that says
/// nothing before `deadline` returns `Ok(false)` — the transfer is not confirmed, which is not the same as failed.
pub fn await_confirmation(
    link: &mut PeerLink,
    transfer_id: TransferId,
    deadline: std::time::Instant,
) -> Result<bool, SessionError> {
    loop {
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        // ★ Read here rather than through `read_control`, because that helper's `PeerFinished` means "some completion
        // arrived" — and the receiver sends a `progress` report after **every** block, right up to the end. An earlier
        // version treated the last of those as the confirmation and returned before the real one arrived, so the sender
        // reported a broken link while the file had landed byte-for-byte. Only a completion counts here.
        //
        // A timeout is "nothing yet" rather than a failure, so the wait ends on the caller's deadline and not on a socket
        // judgement about the link.
        let inbound = match link.receive_inbound() {
            Ok(inbound) => inbound,
            Err(LinkError::TimedOut) => {
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                continue;
            }
            Err(error) => {
                return Err(SessionError::Link(error));
            }
        };
        match inbound {
            // A block at the sending end belongs to a transfer this kernel is not running the receiving half of.
            Inbound::Block { .. } => {
                return Err(SessionError::Payload {
                    message: "control",
                    why: "a block arrived at the sending end".to_owned(),
                });
            }
            Inbound::Envelope(envelope) => {
                match classify(&envelope) {
                Some(Message::Complete) => {
                    let confirmation: TransferComplete = payload_of(&envelope, "complete")?;
                    if confirmation.transfer_id != transfer_id {
                        return Err(SessionError::WrongTransfer {
                            found: confirmation.transfer_id.to_string(),
                            expected: transfer_id.to_string(),
                        });
                    }
                    return Ok(true);
                }
                // The receiver still talking about blocks. Skipped, because the confirmation comes after the last of them.
                Some(Message::Progress) => {
                    let progress: TransferProgress = payload_of(&envelope, "progress")?;
                    if progress.transfer_id != transfer_id {
                        return Err(SessionError::WrongTransfer {
                            found: progress.transfer_id.to_string(),
                            expected: transfer_id.to_string(),
                        });
                    }
                }
                Some(Message::Abort) => {
                    let abort: TransferAbort = payload_of(&envelope, "abort")?;
                    return Err(SessionError::Payload {
                        message: "abort",
                        why: format!("the receiver refused the file: {:?}", abort.reason),
                    });
                }
                // Another feature's message, which a transfer must not swallow.
                _ => return Ok(false),
            }
            },
        }
    }
}

/// The one-shot send: propose, move every block, complete, and wait for the confirmation.
///
/// # Errors
///
/// [`SessionError`] for any failure of the link, the file or the messages. A transfer that runs out of time is **not** an
/// error — it returns the events it managed, and the caller decides whether to keep waiting.
pub fn send_file(
    link: &mut PeerLink,
    path: &Path,
    chunk_size: u32,
    trace_id: TraceId,
    now_ms: i64,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    let mut sender = TransferSender::open(path, chunk_size)?;
    run_transfer(link, &mut sender, trace_id, now_ms, deadline)
}

/// Reads a digest's algorithm and value, for a report.
#[must_use]
pub fn describe(digest: &SriDigest) -> String {
    format!("{}:{}", digest.algorithm().prefix(), digest.encoded())
}

/// A bundle's one-shot send: the same four steps, with a request that says what it is.
///
/// # Why a second function rather than an argument on [`send_file`]
///
/// The two differ in exactly one thing — the metadata the receiver builds its decision from — and that one thing is
/// decided by *what is being sent*, not by how the transfer runs. An `Option<PluginId>` on `send_file` would make every
/// existing caller state which of the two they meant, in a signature about bytes rather than about plugins.
///
/// # Errors
///
/// The same as [`send_file`]: any failure of the link, the file or the messages.
pub fn send_bundle(
    link: &mut PeerLink,
    path: &Path,
    round: &crate::plugin_sync::SyncRound,
    trace_id: TraceId,
    now_ms: i64,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    // The chunk size is the kernel's rather than the caller's, which is why this takes one argument fewer than
    // `send_file`: a bundle is sent by the daemon on a plugin's behalf, and neither of them has a view about how many
    // bytes should travel in one block.
    let mut sender = TransferSender::open_bundle(path, crate::transfer::DEFAULT_CHUNK_SIZE, round)?;
    run_transfer(link, &mut sender, trace_id, now_ms, deadline)
}

/// Proposes, moves every block, completes, and waits for the confirmation.
///
/// Extracted when the second caller appeared, because the four steps are the transfer's and not the payload's: a bundle
/// and a screenshot take the same route, and the only thing that differs is already in the sender.
fn run_transfer(
    link: &mut PeerLink,
    sender: &mut TransferSender,
    trace_id: TraceId,
    now_ms: i64,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    let mut events = vec![propose(link, sender, trace_id, now_ms)?];
    events.extend(send_blocks(link, sender, deadline)?);
    if sender.is_complete() {
        events.push(complete(link, sender, trace_id, now_ms)?);
        // ★ And now the wait the protocol asks for. `events` gains a `Verified` only when the receiver has actually said so,
        // which is what makes a caller's report of success mean something.
        let confirmed = await_confirmation(link, sender.transfer_id(), deadline)?;
        if confirmed {
            events.push(SessionEvent::Verified {
                transfer_id: sender.transfer_id(),
                digest: sender.digest().encoded().to_owned(),
            });
        }
    }
    Ok(events)
}
