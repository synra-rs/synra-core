//! Proposal and bounded block window, driven by receiver acknowledgements.

use synra_protocol::ids::TraceId;
use synra_protocol::session::ProgressBitmap;

use crate::link::PeerLink;
use crate::transfer::TransferSender;

use super::super::types::{SessionError, SessionEvent};
use super::super::wire::{Message, envelope_for};
use super::control::Control;
use super::prepared::{SendContext, SendOptions, check_transfer};

/// Maximum blocks awaiting acknowledgement; reads free slots before more writes.
pub const WINDOW_BLOCKS: usize = 4;

/// Proposes a transfer and reports what was proposed.
///
/// # Errors
/// Returns an envelope or link failure.
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
        byte_length: request.byte_length,
        total_blocks: u32::try_from(sender.blocks().len()).unwrap_or(u32::MAX),
    })
}

/// Sends and awaits acknowledgement for every block, without proposing or completing.
///
/// Full host workflows should use [super::send_prepared] instead.
///
/// # Errors
/// Returns deadline expiry, peer refusal, invalid progress, or a file/link failure.
pub fn send_blocks(
    link: &mut PeerLink,
    sender: &mut TransferSender,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    let previous = link.timeout_overrides();
    let options = SendOptions::new(TraceId::new(), 0, deadline);
    let mut context = SendContext::new(options, || false, |_, _| {}, link.write_deadline());
    let outcome = send_observed(link, sender, &mut context);
    link.set_read_timeout(previous.0);
    link.set_write_timeout(previous.1);
    outcome
}

pub(super) fn send_observed(
    link: &mut PeerLink,
    sender: &mut TransferSender,
    context: &mut SendContext<impl Fn() -> bool, impl FnMut(u32, u32)>,
) -> Result<Vec<SessionEvent>, SessionError> {
    let total = u32::try_from(sender.blocks().len()).unwrap_or(u32::MAX);
    let mut pending = sender.outstanding().into_iter().peekable();
    // Only the bounded active window needs repair bookkeeping.
    let mut in_flight: Vec<(u32, bool)> = Vec::with_capacity(WINDOW_BLOCKS);
    let mut events = Vec::new();
    let mut done = 0;
    let mut previous = ProgressBitmap::empty(total);
    loop {
        while in_flight.len() < WINDOW_BLOCKS {
            let Some(index) = pending.next() else { break };
            context.prepare_write(link)?;
            let data = sender.read_block(index)?;
            link.send_chunk(index, &data)?;
            sender.mark_sent(index);
            in_flight.push((index, false));
        }
        if in_flight.is_empty() && pending.peek().is_none() {
            return Ok(events);
        }
        let Some(control) = context.read(link)? else {
            continue;
        };
        let progress = match control {
            Control::Progress(progress) => progress,
            Control::Abort(notice) => {
                check_transfer(notice.transfer_id, sender.transfer_id())?;
                return Err(SessionError::Aborted {
                    reason: notice.reason,
                });
            }
            Control::Complete(confirmation) => {
                check_transfer(confirmation.transfer_id, sender.transfer_id())?;
                return Err(SessionError::Payload {
                    message: "complete",
                    why: "confirmation arrived before the sender completed".to_owned(),
                });
            }
        };
        check_transfer(progress.transfer_id, sender.transfer_id())?;
        if progress.total_blocks != total {
            return Err(SessionError::BadProgress(
                "block count differs from the proposal".to_owned(),
            ));
        }
        let bitmap = ProgressBitmap::from_bytes(progress.received, total)
            .map_err(|why| SessionError::BadProgress(why.to_owned()))?;
        if !sender.acknowledges_only_sent(&bitmap) {
            return Err(SessionError::BadProgress(
                "the peer acknowledged an unsent block".to_owned(),
            ));
        }
        let acknowledged = bitmap.received_count();
        if previous
            .as_bytes()
            .iter()
            .zip(bitmap.as_bytes())
            .any(|(old, new)| old & !new != 0)
        {
            return Err(SessionError::BadProgress(
                "acknowledged block count regressed".to_owned(),
            ));
        }
        if acknowledged > done {
            done = acknowledged;
            context.advanced(done, total);
        }
        in_flight.retain(|(index, _)| !bitmap.contains(*index));
        if let Some(highest) = bitmap.highest() {
            let mut repaired = Vec::new();
            for (index, already_repaired) in &mut in_flight {
                if *index < highest && !*already_repaired {
                    context.prepare_write(link)?;
                    let data = sender.read_block(*index)?;
                    link.send_chunk(*index, &data)?;
                    *already_repaired = true;
                    repaired.push(*index);
                }
            }
            if !repaired.is_empty() {
                events.push(SessionEvent::Resend {
                    transfer_id: sender.transfer_id(),
                    missing: repaired,
                });
            }
        }
        previous = bitmap;
    }
}
