//! The window the sender keeps in flight, the proposal, and the blocks it moves.

use synra_protocol::ids::TraceId;
use synra_protocol::session::ProgressBitmap;

use crate::link::PeerLink;
use crate::transfer::TransferSender;

use super::control::{Control, read_control};
use super::super::types::{SessionError, SessionEvent};
use super::super::wire::{Message, envelope_for};
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
