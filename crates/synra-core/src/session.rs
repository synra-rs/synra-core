//! Moving a file, once the pieces exist.
//!
//! # What was missing
//!
//! [`crate::transfer`] splits a file and checks a digest; [`crate::link`] carries blocks. Neither knows about the other, and
//! nobody was driving them — so a `TransferRequest` was never sent, a block never left memory, and a `progress` report had
//! nobody to answer it. That driving is this module, and it is the difference between "the pieces exist" and "a file moves".
//!
//! # The shape of a transfer, as the protocol defines it
//!
//! ```text
//! control plane (JSON envelopes)          data plane (ChunkFrame)
//!   file.transfer.request   ──────▶
//!   file.transfer.chunk × N ──────▶         ★ the blocks themselves
//!                           ◀────── file.transfer.progress
//!   file.transfer.complete  ──────▶
//!                           ◀────── file.transfer.complete   (the confirmation)
//! ```
//!
//! # Why the blocks are not simply written in a loop
//!
//! Because a link is not reliable and a receiver is not silent. A sender that wrote every block and then waited for one
//! acknowledgement would be one that **cannot hear a resend request until it has finished talking** — and the receiver's
//! `progress` report is the only thing that says which blocks were lost. So the sender reads between blocks: it sends a
//! window, listens for a report, and fills whatever the report says is missing. A dropped block costs a re-send; it does
//! not cost the transfer.
//!
//! # Why the digest is checked at the end and nowhere else
//!
//! Because a per-block check would tell you a block arrived, not that the file did. The one digest over the whole object is
//! what makes "the transfer succeeded" mean something, and it is checked **after** every block is in place — which is why a
//! short block, a reordered splice or a wrong byte all end at the same place: a refusal.

use std::path::{Path, PathBuf};

use synra_protocol::envelope::{Envelope, EnvelopeError, OutboundSpec};
use synra_protocol::event::{EventName, EventNameError};
use synra_protocol::ids::{DeviceId, TraceId, TransferId};
use synra_protocol::session::{
    ProgressBitmap, SriDigest, TransferAbort, TransferAbortReason, TransferComplete, TransferProgress,
    TransferRequest,
};

use crate::link::{Inbound, LinkError, PeerLink};
use crate::transfer::{
    ObjectDigest, TransferError, TransferReceiver, TransferSender,
};

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

/// What one side of a transfer is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// A transfer was proposed.
    Proposed {
        /// Which transfer.
        transfer_id: TransferId,
        /// How large.
        byte_length: u64,
        /// How many blocks.
        total_blocks: u32,
    },
    /// Blocks the receiver is missing, sent back to the sender.
    Resend {
        /// Which transfer.
        transfer_id: TransferId,
        /// Which blocks.
        missing: Vec<u32>,
    },
    /// The sender has sent everything it intends to.
    CompleteSent {
        /// Which transfer.
        transfer_id: TransferId,
    },
    /// The receiver verified the object and confirmed it.
    Verified {
        /// Which transfer.
        transfer_id: TransferId,
        /// The digest that was checked.
        digest: String,
    },
    /// One side gave up.
    Aborted {
        /// Which transfer.
        transfer_id: TransferId,
        /// Why.
        reason: TransferAbortReason,
    },
}

/// Why a transfer session failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The link failed.
    #[error(transparent)]
    Link(#[from] LinkError),

    /// The file could not be split, read or reassembled.
    #[error(transparent)]
    Transfer(#[from] TransferError),

    /// The event name was refused by the protocol.
    #[error("the event name was refused: {0}")]
    Event(#[from] EventNameError),

    /// The envelope could not be built.
    #[error("the message could not be built: {0}")]
    Envelope(#[from] EnvelopeError),

    /// A message was not the shape this side expected.
    #[error("the {message} payload could not be read: {why}")]
    Payload {
        /// Which message.
        message: &'static str,
        /// What the parser said.
        why: String,
    },

    /// A message named a transfer this side is not running.
    ///
    /// # Why this is an error rather than being ignored
    ///
    /// Because two files sent at once would otherwise interleave: a block for the second transfer applied to the first is a
    /// corrupt file that passes no digest and gives no clue why.
    #[error("a message named transfer {found}, and this side is running {expected}")]
    WrongTransfer {
        /// What arrived.
        found: String,
        /// What is in progress.
        expected: String,
    },

    /// The peer's progress bitmap disagreed with the transfer's size.
    #[error("the peer's progress does not match the transfer: {0}")]
    BadProgress(String),

    /// The transfer is not all there and the sender has stopped.
    ///
    /// Reported rather than retried: the sender said it was finished, so asking again would be asking a device that has
    /// nothing more to give.
    #[error("the sender finished with {missing} of {total} blocks missing")]
    Incomplete {
        /// How many.
        missing: usize,
        /// Out of how many.
        total: u32,
    },
}

/// A message family on the control plane.
///
/// # Why the two directions are one enum
///
/// Because a request and a completion travel in both directions — a receiver answers a completion with a completion — and
/// two enums would be two places the event names live. The names are the protocol's either way.
///
/// Public because [`classify`] returns it: a caller dispatching a link's messages needs to name what it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    /// The sender proposes a transfer.
    Request,
    /// A block of data, carried as a frame rather than as an envelope.
    Chunk,
    /// The sender has sent everything, or the receiver confirms it verified.
    Complete,
    /// Either side is giving up.
    Abort,
    /// The receiver reports which blocks it holds.
    Progress,
}

impl Message {
    /// The wire name, which is the protocol's.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Request => synra_protocol::event::DataPlaneEvent::FileTransferRequest.as_str(),
            Self::Chunk => synra_protocol::event::DataPlaneEvent::FileTransferChunk.as_str(),
            Self::Complete => synra_protocol::event::DataPlaneEvent::FileTransferComplete.as_str(),
            Self::Abort => synra_protocol::event::DataPlaneEvent::FileTransferAbort.as_str(),
            Self::Progress => synra_protocol::event::DataPlaneEvent::FileTransferProgress.as_str(),
        }
    }
}

/// Builds a control-plane envelope for a transfer.
///
/// # Why every transfer message goes through here
///
/// Because the event name, the addressing and the trace have to be right on each one, and six call sites is six chances to
/// get one of them wrong. The trace is the caller's, so every message of one user action shares it.
fn envelope_for<P: serde::Serialize>(
    message: Message,
    from: DeviceId,
    to: DeviceId,
    trace_id: TraceId,
    sent_at_ms: i64,
    payload: &P,
) -> Result<Envelope, SessionError> {
    let event = EventName::parse(message.name())?;
    Ok(Envelope::outbound(
        OutboundSpec { event, target: to, from, trace_id, sent_at_ms, ttl_ms: None },
        Some(payload),
    )?)
}

/// Reads an envelope's payload into a type.
///
/// # Why a `&RawValue` is parsed here rather than a tree
///
/// Because that is how the protocol carries a payload: the envelope holds the bytes and this is the first point that knows
/// what shape they should be. Parsing into a tree first would allocate per field for every message.
fn payload_of<T: for<'de> serde::Deserialize<'de>>(
    envelope: &Envelope,
    message: &'static str,
) -> Result<T, SessionError> {
    let raw = envelope.payload.as_ref().ok_or_else(|| SessionError::Payload {
        message,
        why: "the envelope carries no payload".to_owned(),
    })?;
    serde_json::from_str(raw.get()).map_err(|error| SessionError::Payload {
        message,
        why: error.to_string(),
    })
}

/// Whether an envelope is one of the transfer family.
///
/// Returns which, so a caller can dispatch without parsing the payload of a message that is not for it — which matters,
/// because a link carries every other kind of message too.
#[must_use]
pub fn classify(envelope: &Envelope) -> Option<Message> {
    let name = envelope.event.as_str();
    [
        Message::Request,
        Message::Chunk,
        Message::Complete,
        Message::Abort,
        Message::Progress,
    ]
    .into_iter()
    .find(|message| message.name() == name)
}

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

/// What a receiver did with one inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Received {
    /// A transfer was proposed and accepted; the receiver is ready for blocks.
    Accepted {
        /// Which transfer.
        transfer_id: TransferId,
        /// Where the file is being written.
        path: PathBuf,
    },
    /// A block was stored.
    Block {
        /// Which block.
        index: u32,
        /// Whether it had already arrived.
        duplicate: bool,
    },
    /// The sender says it is done, and the object verified.
    Verified {
        /// Which transfer.
        transfer_id: TransferId,
        /// The digest that matched.
        digest: String,
    },
    /// The sender says it is done, and the object did not verify.
    Failed {
        /// Which transfer.
        transfer_id: TransferId,
        /// Why.
        why: String,
    },
    /// The peer gave up.
    Aborted {
        /// Which transfer.
        transfer_id: TransferId,
        /// Why.
        reason: TransferAbortReason,
    },
    /// A message this receiver has nothing to do with.
    Ignored,
}

/// A receiver's side of one transfer.
pub struct Receiving {
    /// The transfer being filled.
    receiver: TransferReceiver,
    /// The trace this transfer's messages share.
    trace_id: TraceId,
}

impl std::fmt::Debug for Receiving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiving")
            .field("transfer_id", &self.receiver.transfer_id())
            .field("received", &self.receiver.received_count())
            .finish()
    }
}

impl Receiving {
    /// Accepts a proposal and prepares to fill a file.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when the request cannot be read, and [`TransferError`] when the destination cannot be written.
    pub fn accept(
        envelope: &Envelope,
        destination: &Path,
        trace_id: TraceId,
    ) -> Result<Self, SessionError> {
        let request: TransferRequest = payload_of(envelope, "request")?;
        let receiver = TransferReceiver::accept(&request, destination)?;
        Ok(Self { receiver, trace_id })
    }

    /// Which transfer this is.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.receiver.transfer_id()
    }

    /// The trace the messages share.
    #[must_use]
    pub const fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// How many blocks have arrived.
    #[must_use]
    pub fn received_count(&self) -> u32 {
        self.receiver.received_count()
    }

    /// Which blocks are still missing.
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        self.receiver.bitmap().missing()
    }

    /// Where the file is being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.receiver.path()
    }

    /// How large the object is.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.receiver.byte_length()
    }

    /// The receiver underneath, for a caller that needs to report progress or check a bitmap.
    ///
    /// # Why this is exposed rather than wrapped
    ///
    /// Because [`report_progress`] takes it, and a caller driving its own loop needs to call that. Wrapping every method of
    /// the inner type would be a second interface to keep in step with the first, for no gain.
    #[must_use]
    pub const fn receiver(&self) -> &TransferReceiver {
        &self.receiver
    }

    /// Takes one inbound message.
    ///
    /// # Errors
    ///
    /// [`SessionError`] for a link failure or a malformed message. A block that does not belong is refused rather than
    /// written, and a completion that does not verify is reported as [`Received::Failed`] rather than as an error — the
    /// transfer ended, and *how* it ended is the interesting part.
    pub fn absorb(
        &mut self,
        link: &mut PeerLink,
        now_ms: i64,
        deadline: std::time::Instant,
    ) -> Result<Received, SessionError> {
        // ★ A quiet link is not a closed one, and this is the read a receiver spends most of a transfer sitting on. An
        // earlier version propagated the socket's timeout with `?`, so the caller saw a link failure and closed the
        // connection — while the sender's completion was on its way down the same stream, one frame behind the last block.
        // That is what made the confirmation arrive about half the time: whichever of the two got there first decided it.
        //
        // The deadline is what bounds the wait, so a peer that genuinely goes away is still noticed; a message that is
        // simply late is still read.
        let inbound = loop {
            match link.receive_inbound() {
                Ok(inbound) => break inbound,
                Err(LinkError::TimedOut) => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(Received::Ignored);
                    }
                }
                Err(error) => return Err(SessionError::Link(error)),
            }
        };
        match inbound {
            // ★ A block at the receiving end is the point of the whole exercise. The index in the frame is the block's
            // place in the object, which is why the block's own bytes need no header of their own.
            Inbound::Block { chunk_id, data } => {
                let absorbed = self.receiver.absorb(chunk_id, &data)?;
                // A duplicate is reported as what it is rather than as a new block: the sender uses this to stop
                // re-sending, and a receiver that said "stored" twice would make it re-send for ever.
                Ok(Received::Block {
                    index: chunk_id,
                    duplicate: matches!(absorbed, crate::transfer::Absorbed::Duplicate),
                })
            }
            Inbound::Envelope(envelope) => match classify(&envelope) {
                Some(Message::Complete) => {
                    let complete: TransferComplete = payload_of(&envelope, "complete")?;
                    if complete.transfer_id != self.receiver.transfer_id() {
                        return Err(SessionError::WrongTransfer {
                            found: complete.transfer_id.to_string(),
                            expected: self.receiver.transfer_id().to_string(),
                        });
                    }
                    match self.receiver.finish(&complete.digest) {
                        Ok(digest) => {
                            // ★ The confirmation goes back, and it carries the digest **the receiver verified** — not a
                            // second opinion. The design's `CompletionMismatch` check is for the sender's message
                            // disagreeing with its own earlier request, which `finish` refuses before reading the file.
                            let confirmation = TransferComplete {
                                transfer_id: self.receiver.transfer_id(),
                                digest: complete.digest,
                            };
                            let reply = envelope_for(
                                Message::Complete,
                                link.local(),
                                link.peer(),
                                self.trace_id,
                                now_ms,
                                &confirmation,
                            )?;
                            link.send(&reply)?;
                            Ok(Received::Verified {
                                transfer_id: self.receiver.transfer_id(),
                                digest: digest.encoded().to_owned(),
                            })
                        }
                        Err(error) => {
                            // The object did not verify. The sender is told why, so it can distinguish "the bytes were
                            // wrong" from "you never finished".
                            let reason = match error {
                                TransferError::Incomplete { .. } => TransferAbortReason::IoError,
                                _ => TransferAbortReason::DigestMismatch,
                            };
                            let notice = TransferAbort {
                                transfer_id: self.receiver.transfer_id(),
                                reason,
                            };
                            let reply = envelope_for(
                                Message::Abort,
                                link.local(),
                                link.peer(),
                                self.trace_id,
                                now_ms,
                                &notice,
                            )?;
                            link.send(&reply)?;
                            Ok(Received::Failed {
                                transfer_id: self.receiver.transfer_id(),
                                why: error.to_string(),
                            })
                        }
                    }
                }
                Some(Message::Abort) => {
                    let abort: TransferAbort = payload_of(&envelope, "abort")?;
                    Ok(Received::Aborted { transfer_id: abort.transfer_id, reason: abort.reason })
                }
                // Anything else on the link belongs to somebody else, and a transfer that swallowed it would be one that
                // broke every other feature on the same connection.
                _ => Ok(Received::Ignored),
            },
        }
    }

    /// Finishes the transfer without a completion message, for a caller that verified some other way.
    ///
    /// # Errors
    ///
    /// [`TransferError`] when the object does not verify.
    pub fn finish_without_completion(&mut self) -> Result<ObjectDigest, TransferError> {
        // A completion that repeats the request's own digest, so the same checks run: an incomplete object is reported as
        // incomplete and wrong bytes as a mismatch.
        let expected = self.receiver.expected_digest().clone();
        self.receiver.finish(&expected)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::Flags;
    use std::io::Write as _;

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    /// A temporary directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "synra-session-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temp directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut handle = std::fs::File::create(&path).expect("creates");
        handle.write_all(bytes).expect("writes");
        handle.flush().expect("flushes");
        path
    }

    /// Two connected links, as a session would have.
    fn connected() -> (PeerLink, PeerLink) {
        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let address = listener.local_addr().expect("an address");
        let dialer = std::net::TcpStream::connect(address).expect("connects");
        let (accepted, _) = listener.accept().expect("accepts");
        let agreed = synra_protocol::handshake::Agreed {
            common: Vec::new(),
            missing_required: Vec::new(),
        };
        (
            PeerLink::new(dialer, device(A), device(B), agreed.clone(), Flags::no_timeout()),
            PeerLink::new(accepted, device(B), device(A), agreed, Flags::no_timeout()),
        )
    }

    fn later() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(10)
    }

    /// An envelope carrying a throwaway payload of the right event.
    fn envelope_of(message: Message) -> Envelope {
        envelope_for(message, device(A), device(B), TraceId::new(), 0, &serde_json::json!({}))
            .expect("builds")
    }

    // ── Names and classification ──────────────────────────────────────────────────────────────────

    #[test]
    fn every_message_name_is_one_the_protocol_declares() {
        // ★ The names are the protocol's, and a transfer that used a name outside its set would be a message the far end
        // refuses as an unknown event.
        for message in [
            Message::Request,
            Message::Chunk,
            Message::Complete,
            Message::Abort,
            Message::Progress,
        ] {
            assert!(
                EventName::parse(message.name()).is_ok(),
                "{} is not a name this build accepts",
                message.name()
            );
            assert!(
                synra_protocol::event::DataPlaneEvent::from_str_opt(message.name()).is_some(),
                "{} is not a data-plane event",
                message.name()
            );
        }
    }

    #[test]
    fn a_classified_message_is_recognised_and_a_stranger_is_not() {
        // ★ A link carries every kind of message, so a dispatcher that claimed an unrelated event would break whichever
        // feature owned it.
        assert_eq!(classify(&envelope_of(Message::Request)), Some(Message::Request));
        assert_eq!(classify(&envelope_of(Message::Progress)), Some(Message::Progress));

        let stranger = Envelope::outbound(
            OutboundSpec {
                event: EventName::parse("device.ping").expect("a name"),
                target: device(B),
                from: device(A),
                trace_id: TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&serde_json::Value>,
        )
        .expect("builds");
        assert_eq!(classify(&stranger), None, "an unrelated event was claimed");
    }

    // ── A whole transfer, with no socket ──────────────────────────────────────────────────────────

    #[test]
    fn a_file_moves_from_one_side_to_the_other() {
        // ★ The whole point of this module: propose, move every block, confirm. The pieces have their own tests; what none
        // of those can see is the *sequence*, and this is the sequence a real transfer takes.
        let dir = TempDir::new("whole");
        let content: Vec<u8> = (0..=255u8).cycle().take(20_000).collect();
        let source = file(&dir, "source.bin", &content);
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let transfer = TransferSender::open(&source, 1_024).expect("opens");
        let trace = TraceId::new();

        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");
        assert_eq!(receiving.transfer_id(), transfer.transfer_id());

        // Every block, straight through — the reliable-link case.
        for block in transfer.blocks() {
            let data = transfer.read_block(block.index).expect("reads");
            side_a.send_chunk(block.index, &data).expect("sends");
            match receiving.absorb(&mut side_b, 0, later()).expect("absorbs") {
                Received::Block { index, duplicate } => {
                    assert_eq!(index, block.index);
                    assert!(!duplicate);
                }
                other => panic!("expected a stored block, got {other:?}"),
            }
        }

        complete(&mut side_a, &transfer, trace, 0).expect("completes");
        match receiving.absorb(&mut side_b, 0, later()).expect("absorbs") {
            Received::Verified { transfer_id, digest } => {
                assert_eq!(transfer_id, transfer.transfer_id());
                assert_eq!(digest, transfer.digest().encoded());
            }
            other => panic!("expected a verification, got {other:?}"),
        }
        assert_eq!(std::fs::read(&destination).expect("reads back"), content);
    }

    #[test]
    fn the_receiver_confirms_back_and_the_sender_hears_it() {
        // ★ The confirmation is what tells a sender the file arrived, and it travels as a completion — the same message
        // kind, in the other direction.
        let dir = TempDir::new("confirm");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let transfer = TransferSender::open(&source, 4).expect("opens");
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        for block in transfer.blocks() {
            let data = transfer.read_block(block.index).expect("reads");
            side_a.send_chunk(block.index, &data).expect("sends");
            receiving.absorb(&mut side_b, 0, later()).expect("absorbs");
        }
        complete(&mut side_a, &transfer, trace, 0).expect("completes");
        receiving.absorb(&mut side_b, 0, later()).expect("verifies");

        // The sender reads the confirmation.
        let Inbound::Envelope(envelope) = side_a.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        assert_eq!(classify(&envelope), Some(Message::Complete));
        let confirmation: TransferComplete = payload_of(&envelope, "complete").expect("reads");
        assert_eq!(confirmation.transfer_id, transfer.transfer_id());
        assert_eq!(confirmation.digest.encoded(), transfer.digest().encoded());
    }

    // ── A dropped block, and the report that rescues it ───────────────────────────────────────────

    #[test]
    fn a_progress_report_tells_the_sender_which_blocks_to_send_again() {
        // ★ The reason the sender reads between windows. A block that never arrived is reported in a bitmap, and the
        // sender re-sends exactly that one — not the whole file, and not nothing.
        let dir = TempDir::new("resend");
        let content: Vec<u8> = (0..=255u8).cycle().take(4_000).collect();
        let source = file(&dir, "source.bin", &content);
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let transfer = TransferSender::open(&source, 512).expect("opens");
        let trace = TraceId::new();
        let request = transfer.request();
        let mut receiving = TransferReceiver::accept(&request, &destination).expect("accepts");

        // Everything except block 1, which "was lost".
        for block in transfer.blocks() {
            if block.index == 1 {
                continue;
            }
            let data = transfer.read_block(block.index).expect("reads");
            side_a.send_chunk(block.index, &data).expect("sends");
            let Inbound::Block { chunk_id, data } = side_b.receive_inbound().expect("receives")
            else {
                panic!("expected a block");
            };
            receiving.absorb(chunk_id, &data).expect("absorbs");
        }

        report_progress(&mut side_b, &receiving, trace, 0).expect("reports");
        let Inbound::Envelope(envelope) = side_a.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        assert_eq!(classify(&envelope), Some(Message::Progress));
        let progress: TransferProgress = payload_of(&envelope, "progress").expect("reads");
        assert_eq!(progress.transfer_id, transfer.transfer_id());
        let bitmap = ProgressBitmap::from_bytes(progress.received, progress.total_blocks)
            .expect("a matching bitmap");
        assert_eq!(bitmap.missing(), vec![1]);

        // And that one block completes the transfer.
        let data = transfer.read_block(1).expect("reads");
        side_a.send_chunk(1, &data).expect("sends");
        let Inbound::Block { chunk_id, data } = side_b.receive_inbound().expect("receives") else {
            panic!("expected a block");
        };
        receiving.absorb(chunk_id, &data).expect("absorbs");
        receiving.finish(&request.digest).expect("verifies");
        assert_eq!(std::fs::read(&destination).expect("reads back"), content);
    }

    #[test]
    fn a_progress_bitmap_that_disagrees_with_the_size_is_refused() {
        // A bitmap of the wrong length means the two sides differ about the transfer's size, which is a disagreement no
        // amount of re-sending fixes.
        assert!(ProgressBitmap::from_bytes(vec![0, 0], 2).is_err());
        assert!(ProgressBitmap::from_bytes(vec![0], 2).is_ok());
    }



    // ── The whole round trip, both ends at once ───────────────────────────────────────────────────

    #[test]
    fn a_receiver_waits_out_a_quiet_link_rather_than_abandoning_the_transfer() {
        // ★ The read a receiver spends most of a transfer sitting on, and the bug that made the completion arrive about half
        // the time: this used to propagate the socket's timeout with `?`, so the caller saw a link failure and closed the
        // connection while the sender's completion was one frame behind the last block. The deadline is what bounds the
        // wait — not the socket — so a message that is merely late is still read.
        let dir = TempDir::new("quiet-link");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let destination = dir.path().join("copy.bin");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        // Production flags, so the socket has the short real timeout that used to end the transfer.
        let (mut side_a, mut side_b) = connected_with(Flags::production());
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected a proposal");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        // Nothing is sent for longer than the link's read timeout, then one block arrives. A receiver that gave up at the
        // timeout would never see it.
        let quiet_for = synra_protocol::limits::HELLO_TIMEOUT + std::time::Duration::from_millis(400);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(quiet_for);
            let data = transfer.read_block(0).expect("reads");
            side_a.send_chunk(0, &data).expect("sends");
            side_a
        });

        // A deadline far beyond the quiet period: the wait is bounded by this, not by the socket.
        let received = receiving
            .absorb(&mut side_b, 0, later())
            .expect("a quiet link is not a failure");
        assert!(
            matches!(received, Received::Block { index: 0, .. }),
            "the receiver gave up on a quiet link: {received:?}"
        );
        let _ = writer.join().expect("the writer finished");
    }

    /// Two connected links under given flags.
    fn connected_with(flags: Flags) -> (PeerLink, PeerLink) {
        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let address = listener.local_addr().expect("an address");
        let dialer = std::net::TcpStream::connect(address).expect("connects");
        let (accepted, _) = listener.accept().expect("accepts");
        let agreed = synra_protocol::handshake::Agreed {
            common: Vec::new(),
            missing_required: Vec::new(),
        };
        (
            PeerLink::new(dialer, device(A), device(B), agreed.clone(), flags),
            PeerLink::new(accepted, device(B), device(A), agreed, flags),
        )
    }

    #[test]
    fn a_file_moves_and_the_sender_is_told_it_arrived() {
        // ★ This is the flow a daemon runs, and it is the one that was broken: `send_file` on one thread, a receiver
        // answering on the other, **production flags** so the socket has the real six-second read timeout, and a report
        // after every block exactly as the daemon sends. An earlier version moved the file byte-for-byte and then reported
        // a broken link, and nothing smaller than this test could tell the two apart.
        let dir = TempDir::new("round-trip");
        // ★ The daemon's own figures, which is the point: an earlier version of this test used a small chunk size and it
        // passed, while the daemon — which uses `DEFAULT_CHUNK_SIZE` — moved the file and then reported a broken link. A
        // test that does not use the sender's real block size cannot see a block-size problem.
        let content: Vec<u8> = (0..=255u8).cycle().take(600_000).collect();
        let source = file(&dir, "source.bin", &content);
        let destination = dir.path().join("copy.bin");
        let target = destination.clone();

        let (mut side_a, side_b) = connected_with(Flags::production());
        let trace = TraceId::new();

        // The receiver, exactly as the daemon drives it: read the proposal, absorb, report, and answer the completion.
        let reports = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reports_in = std::sync::Arc::clone(&reports);
        let receiver = std::thread::spawn(move || {
            let mut side_b = side_b;
            let proposal = side_b.receive_inbound().expect("receives the proposal");
            let Inbound::Envelope(envelope) = proposal else {
                panic!("expected a proposal");
            };
            let mut receiving = Receiving::accept(&envelope, &target, trace).expect("accepts");
            let generous = || std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                match receiving.absorb(&mut side_b, 0, generous()).expect("absorbs") {
                    Received::Block { .. } => {
                        report_progress(&mut side_b, receiving.receiver(), trace, 0)
                            .expect("reports");
                        reports_in.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Received::Verified { digest, .. } => return digest,
                    other => panic!("the receiver stopped early: {other:?}"),
                }
            }
        });

        let events = send_file(
            &mut side_a,
            &source,
            crate::transfer::DEFAULT_CHUNK_SIZE,
            trace,
            0,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        )
        .expect("sends");

        let digest = receiver.join().expect("the receiver finished");
        assert!(
            events.iter().any(|event| matches!(event, SessionEvent::Verified { .. })),
            "the sender was never told the file arrived: {events:?}"
        );
        assert_eq!(std::fs::read(&destination).expect("reads back"), content);
        assert!(!digest.is_empty());
    }

    // ── Receiving ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_receiver_accepts_a_proposal_and_reports_where_it_is_writing() {
        let dir = TempDir::new("accept");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");

        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");
        assert_eq!(receiving.transfer_id(), transfer.transfer_id());
        assert_eq!(receiving.path(), destination);
        assert_eq!(receiving.missing().len(), 2);
    }

    #[test]
    fn a_message_from_another_feature_is_not_swallowed_by_the_transfer() {
        // ★ A transfer must not eat every message on the link, or it would break whatever else is using the connection.
        let dir = TempDir::new("ignored");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        let unrelated = Envelope::outbound(
            OutboundSpec {
                event: EventName::parse("device.ping").expect("a name"),
                target: device(B),
                from: device(A),
                trace_id: trace,
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&serde_json::Value>,
        )
        .expect("builds");
        side_a.send(&unrelated).expect("sends");

        assert_eq!(
            receiving.absorb(&mut side_b, 0, later()).expect("absorbs"),
            Received::Ignored
        );
    }

    #[test]
    fn an_abort_from_the_peer_ends_the_transfer_with_its_reason() {
        let dir = TempDir::new("abort");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        abort(&mut side_a, transfer.transfer_id(), TransferAbortReason::UserCancelled, trace, 0)
            .expect("aborts");
        assert_eq!(
            receiving.absorb(&mut side_b, 0, later()).expect("absorbs"),
            Received::Aborted {
                transfer_id: transfer.transfer_id(),
                reason: TransferAbortReason::UserCancelled,
            }
        );
    }

    #[test]
    fn a_completion_for_another_transfer_is_refused() {
        // ★ Two files at once would otherwise be finalised against each other's digests.
        let dir = TempDir::new("wrong-completion");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        let stray = TransferComplete {
            transfer_id: TransferId::new(),
            digest: transfer.digest().as_sri().clone(),
        };
        let envelope =
            envelope_for(Message::Complete, device(A), device(B), trace, 0, &stray).expect("builds");
        side_a.send(&envelope).expect("sends");

        match receiving.absorb(&mut side_b, 0, later()) {
            Err(SessionError::WrongTransfer { .. }) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_completion_that_does_not_verify_is_reported_and_the_peer_is_told_why() {
        // ★ A digest mismatch and a missing block need different answers from the sender, so the transfer reports which it
        // was — and the peer hears about it rather than being left waiting for a confirmation that will not come.
        let dir = TempDir::new("no-verify");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        // The completion arrives with no blocks sent at all.
        complete(&mut side_a, &transfer, trace, 0).expect("completes");
        match receiving.absorb(&mut side_b, 0, later()).expect("absorbs") {
            Received::Failed { transfer_id, why } => {
                assert_eq!(transfer_id, transfer.transfer_id());
                assert!(!why.is_empty());
            }
            other => panic!("expected a failure, got {other:?}"),
        }

        // And the sender is told, with a reason.
        let Inbound::Envelope(envelope) = side_a.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        assert_eq!(classify(&envelope), Some(Message::Abort));
        let notice: TransferAbort = payload_of(&envelope, "abort").expect("reads");
        assert_eq!(notice.reason, TransferAbortReason::IoError);
    }

    // ── The one-shot ──────────────────────────────────────────────────────────────────────────────

}
