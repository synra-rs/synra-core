//! Reporting progress, completing a transfer, and aborting one.

use synra_protocol::session::{TransferAbort, TransferAbortReason, TransferComplete};

use crate::link::PeerLink;

use super::super::types::{SessionError, SessionEvent};
use super::super::wire::{Message, envelope_for};
use synra_protocol::ids::{TraceId, TransferId};
use synra_protocol::session::TransferProgress;
use crate::transfer::{TransferReceiver, TransferSender};

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
