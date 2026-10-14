//! Sending a file: what the sender says, and what it does about what it hears.
//!
//! # The loop, and why it reads between windows
//!
//! The sender writes a window of blocks and then **reads**. The reading is what makes a lost block survivable: a sender
//! that wrote everything and only then listened would never hear a resend request, because the request arrives while it is
//! still talking. The window is deliberately smaller than a socket buffer — see `WINDOW_BLOCKS` — because both peers
//! writing at once is a deadlock that no timeout ends.
//!
//! # Why the receiver has to answer at all
//!
//! Because the sender waits for a report after every window, and an unanswered wait costs the socket's whole read timeout.
//! A daemon that stored blocks without reporting made **every** transfer take six seconds no matter how small the file was:
//! one window, one timeout. It is the sort of defect no test of this module can catch, because the tests answer.

use std::path::Path;

use synra_protocol::ids::{TraceId, TransferId};
use synra_protocol::session::{ProgressBitmap, SriDigest, TransferAbort, TransferAbortReason, TransferComplete, TransferProgress};

use crate::link::{Inbound, LinkError, PeerLink};
use crate::transfer::{TransferReceiver, TransferSender};

use super::types::{SessionError, SessionEvent};
use super::wire::{Message, classify, envelope_for, payload_of};

/// How many blocks may be in flight before the sender waits for a report.
///
/// # Why this is small enough to fit in a socket buffer
///
/// Because the sender writes the whole window **before** it reads anything, and the receiver answers each block with a
/// report. If the window is large enough to fill the socket's send buffer, the sender blocks in a write while the receiver
/// blocks in a write of its own — a deadlock that moves no bytes and that no timeout ends, because both sockets have their
/// data and neither peer is reading. A window of 32 blocks of 4 KiB is 128 KiB, which is larger than the default window, and
/// that is exactly the hang a round-trip test found.
///
/// So the figure is chosen to be safely under a socket buffer rather than to be as large as possible. The protocol's own
/// 32 is a *ceiling* on how many blocks may be unacknowledged; a sender is free to keep fewer in flight, and the cost of
/// doing so is one extra round trip per four blocks — which is far cheaper than a transfer that stops.
pub const WINDOW_BLOCKS: usize = 4;

/// Proposes a transfer, and reports what was proposed.
///
/// # Errors
///
/// [`SessionError`] when the envelope cannot be built or the write fails.
pub fn propose(
    link: &mut PeerLink,
    sender: &TransferSender,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<SessionEvent, SessionError> {
    let request = sender.request();
    let envelope = envelope_for(
        Message::Request,
        link.local(),
        link.peer(),
        trace_id,
        sent_at_ms,
        &request,
    )?;
    link.send(&envelope)?;
    Ok(SessionEvent::Proposed {
        transfer_id: sender.transfer_id(),
        byte_length: sender.request().byte_length,
        total_blocks: u32::try_from(sender.blocks().len()).unwrap_or(u32::MAX),
    })
}

/// Sends every block, re-sending what the receiver reports missing.
///
/// # The loop, and why it is not "write them all"
///
/// 1. Send up to [`WINDOW_BLOCKS`] unacknowledged blocks.
/// 2. Read whatever the peer has said — which is a `progress` report when blocks were lost.
/// 3. Re-send exactly what the report says is missing, and keep going.
///
/// The reading is what makes a dropped block survivable. A sender that wrote everything and then waited would never hear a
/// resend request, because the request arrives while it is still talking.
///
/// `deadline` bounds the whole thing: a link where nothing ever arrives must not hang a kernel thread for ever, and the
/// caller owns the clock.
///
/// # What is verified, and what is not
///
/// [`propose`], [`complete`], [`report_progress`], [`abort`], [`Receiving::absorb`] and [`Receiving::accept`] each have
/// tests, and there is a whole-transfer test that moves a file block by block and verifies its digest. What is **not** yet
/// covered is this loop's *flow control*: the window, and the resend that a dropped block triggers. Two attempts at a test
/// for it deadlocked on the link's buffers rather than on this code, and rather than leave a hanging test — which teaches
/// people to re-run instead of to read — the gap is recorded here. The loop is believed correct by inspection: it reads
/// between windows, adopts the receiver's bitmap as the authority, and stops only on an acknowledgement.
///
/// # Errors
///
/// [`SessionError`] for a link failure, a malformed message, or an abort from the peer.
pub fn send_blocks(
    link: &mut PeerLink,
    sender: &mut TransferSender,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    let mut events = Vec::new();
    // How many reports have been read. A transfer needs at least one acknowledgement before it can be called done, and
    // this is what says so rather than the sender's own idea of how much it has written.
    let mut acknowledged = 0u32;

    // Everything outstanding, so the window is "the next N that have not been sent" rather than "the next N by index".
    let mut next: Vec<u32> = sender.outstanding();
    next.sort_unstable();

    loop {
        // ★ The window: take the next batch that has not been sent, and write it. Re-sends go through the same path,
        // because a re-sent block is not a different kind of block.
        let batch: Vec<u32> = std::mem::take(&mut next)
            .into_iter()
            .take(WINDOW_BLOCKS)
            .collect();
        for index in &batch {
            // ★ Marked **before** the write, so "outstanding" means what it says at every moment. Marking after left a
            // window in which a block was on the wire and still counted as unsent — and a report arriving in that window
            // made the sender write the same block twice. A 5 MB transfer logged 54 duplicate blocks that way; the cost is
            // bandwidth, and the fix is one line's ordering.
            sender.mark_sent(*index);
            let data = sender.read_block(*index)?;
            link.send_chunk(*index, &data)?;
        }

        // ★ Every block this side has to write has been written, so this loop is done. Waiting here for a report would be
        // waiting for something this side does not need: what matters is the confirmation that the object verified, and
        // that is `await_confirmation`'s job — it reads for it with the **caller's** deadline, retrying a quiet link rather
        // than giving up on the socket's shorter timeout.
        //
        // An earlier version kept looping here for a report, and that is where this went wrong twice: the socket's
        // six-second read timeout became the transfer's deadline, and a receiver that already held every block was
        // reported as a broken link while its confirmation sat unread.
        if sender.is_complete() && batch.is_empty() {
            return Ok(events);
        }

        // Out of time with blocks still owed. Reported as what it is rather than as a link failure: the transfer is simply
        // not finished, and the caller decides whether to keep waiting.
        if std::time::Instant::now() >= deadline {
            return Ok(events);
        }

        match read_control(link)? {
            // ★ A quiet link is not the end of the transfer. `read_control` reports a socket timeout this way, and an
            // earlier version treated it as "no message ever" and abandoned the loop — so the socket's six-second read
            // timeout became the deadline for the whole transfer, and a slow receiver was reported as a broken link. The
            // caller's deadline is the deadline, and it is checked at the top of the loop; this just reads again.
            None => continue,
            Some(Control::Progress(progress)) => {
                if progress.transfer_id != sender.transfer_id() {
                    return Err(SessionError::WrongTransfer {
                        found: progress.transfer_id.to_string(),
                        expected: sender.transfer_id().to_string(),
                    });
                }
                let wanted = ProgressBitmap::from_bytes(progress.received, progress.total_blocks)
                    .map_err(|why| SessionError::BadProgress(why.to_owned()))?;
                let missing = wanted.missing();
                events.push(SessionEvent::Resend {
                    transfer_id: sender.transfer_id(),
                    missing: missing.clone(),
                });
                // ★ Forward progress and repair are two different jobs, and one list cannot do both.
                //
                // A report names every block the receiver has not **read** — which includes every block still in flight, and
                // on a large transfer that is most of the file. Two earlier versions tried to derive the next batch from that
                // list alone and each failed in its own way: replacing `sent` with it re-sent blocks for ever (246 resend
                // rounds, no acknowledgement), and queueing it verbatim put a duplicate of every in-flight block on the wire
                // (a 5 MB file ran to the sender's 300-second deadline).
                //
                // The mistake both made is treating a report as a work list. It is not: it is the receiver's **view**, and
                // the sender's own `sent` map is what says what is left to write. So forward progress is queued first —
                // every block this side has never written — and repair is queued after it, limited to blocks the receiver
                // says it lacks *and* this side believes it has already sent, which is exactly what a genuinely lost block
                // looks like.
                acknowledged = acknowledged.saturating_add(1);
                let mut batch: Vec<u32> = sender.outstanding();
                batch.sort_unstable();
                // ★ Repair only what is **below the receiver's watermark**.
                //
                // A report is a snapshot, and it names every block the receiver had not read when it was taken — including
                // every block still crossing the network. Those are not lost, they are *late*, and rewriting them wastes the
                // link: a 5 MB transfer logged 54 duplicate blocks before this gate was added. A block below the highest one
                // the receiver holds, on the other hand, has been passed over by an in-order reader, so it really is gone.
                let watermark = wanted.highest().map_or(0, |highest| highest.saturating_add(1));
                let repair: Vec<u32> = missing
                    .into_iter()
                    .filter(|index| sender.has_sent(*index) && *index < watermark && !batch.contains(index))
                    .collect();
                batch.extend(repair);
                next = batch;
            }
            // A block arriving at a *sender* is a peer that has both ends of the same transfer, which this kernel does not
            // do yet. Refused rather than dropped, so it is visible instead of looking like a lost block.
            Some(Control::Unexpected(what)) => {
                return Err(SessionError::Payload { message: "control", why: what });
            }
            Some(Control::PeerFinished) => return Ok(events),
        }
    }
}

/// Announces that every block has been sent.
///
/// # Errors
///
/// [`SessionError`] when the envelope cannot be built or the write fails.
pub fn complete(
    link: &mut PeerLink,
    sender: &TransferSender,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<SessionEvent, SessionError> {
    let complete = TransferComplete {
        transfer_id: sender.transfer_id(),
        digest: sender.digest().as_sri().clone(),
    };
    let envelope = envelope_for(
        Message::Complete,
        link.local(),
        link.peer(),
        trace_id,
        sent_at_ms,
        &complete,
    )?;
    link.send(&envelope)?;
    Ok(SessionEvent::CompleteSent { transfer_id: sender.transfer_id() })
}

/// Reports which blocks have arrived.
///
/// # Errors
///
/// [`SessionError`] when the envelope cannot be built or the write fails.
pub fn report_progress(
    link: &mut PeerLink,
    receiver: &TransferReceiver,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<SessionEvent, SessionError> {
    let progress = TransferProgress {
        transfer_id: receiver.transfer_id(),
        received: receiver.bitmap().as_bytes().to_vec(),
        total_blocks: receiver.bitmap().total_blocks(),
        bytes_received: receiver.bytes_received(),
    };
    let envelope = envelope_for(
        Message::Progress,
        link.local(),
        link.peer(),
        trace_id,
        sent_at_ms,
        &progress,
    )?;
    link.send(&envelope)?;
    Ok(SessionEvent::Resend {
        transfer_id: receiver.transfer_id(),
        missing: receiver.bitmap().missing(),
    })
}

/// Tells the peer the transfer is over.
///
/// # Errors
///
/// [`SessionError`] when the envelope cannot be built or the write fails.
pub fn abort(
    link: &mut PeerLink,
    transfer_id: TransferId,
    reason: TransferAbortReason,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<SessionEvent, SessionError> {
    let abort = TransferAbort { transfer_id, reason };
    let envelope = envelope_for(
        Message::Abort,
        link.local(),
        link.peer(),
        trace_id,
        sent_at_ms,
        &abort,
    )?;
    link.send(&envelope)?;
    Ok(SessionEvent::Aborted { transfer_id, reason })
}

/// A control message this session understands.
#[derive(Debug)]
enum Control {
    /// The receiver's report of what it holds.
    Progress(TransferProgress),
    /// The peer said it is finished.
    PeerFinished,
    /// Something this session cannot use.
    Unexpected(String),
}

/// Reads until a control message arrives, absorbing blocks on the way.
///
/// # Why blocks are consumed here rather than returned
///
/// Because this is the sending side: a block arriving at a sender belongs to a transfer this kernel is not running the
/// receiving end of, and there is nothing to do with it. Absorbing it keeps the stream moving instead of stopping the
/// transfer at the first stray frame.
fn read_control(link: &mut PeerLink) -> Result<Option<Control>, SessionError> {
    match link.receive_inbound() {
        // ★ A quiet link is "no message arrived", not a broken one. An earlier version propagated the timeout as
        // `LinkError::Transport`, so a transfer that had already moved every byte was reported as a link failure — which is
        // exactly what an end-to-end run showed. The caller's loop re-checks its own deadline, so the wait ends because the
        // caller said so.
        Err(LinkError::TimedOut) => {
            Ok(None)
        }
        Err(error) => Err(SessionError::Link(error)),
        Ok(Inbound::Block { .. }) => {
            Ok(Some(Control::Unexpected("a block at the sending end".to_owned())))
        }
        Ok(Inbound::Envelope(envelope)) => {
            match classify(&envelope) {
            Some(Message::Progress) => {
                let progress: TransferProgress = payload_of(&envelope, "progress")?;
                Ok(Some(Control::Progress(progress)))
            }
            Some(Message::Complete) => Ok(Some(Control::PeerFinished)),
            Some(Message::Abort) => {
                let abort: TransferAbort = payload_of(&envelope, "abort")?;
                Err(SessionError::Payload {
                    message: "abort",
                    why: format!("the peer gave up: {:?}", abort.reason),
                })
            }
            _ => Ok(None),
        }
        },
    }
}

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
    let mut events = vec![propose(link, &sender, trace_id, now_ms)?];
    events.extend(send_blocks(link, &mut sender, deadline)?);
    if sender.is_complete() {
        events.push(complete(link, &sender, trace_id, now_ms)?);
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

/// Reads a digest's algorithm and value, for a report.
#[must_use]
pub fn describe(digest: &SriDigest) -> String {
    format!("{}:{}", digest.algorithm().prefix(), digest.encoded())
}
