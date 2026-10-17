//! Moving a sender's blocks out, one at a time.
//!
//! # Why this is not in the link
//!
//! Because it is the sender's loop, not the socket's: which block comes next, what "sent" means, and when the transfer is done
//! are all [`TransferSender`]'s answers. The socket only carries the bytes — so the send is a **closure** here, and this
//! function is testable without a peer.
//!
//! # What it deliberately does not do
//!
//! Retransmit. A refused block is the caller's to report, because only it knows whether the link is worth retrying with
//! `synra-net`'s backoff or whether the transfer is over.

use crate::transfer::{TransferError, TransferSender};

/// What can stop the loop.
///
/// `#[non_exhaustive]`: a loop that grows a way to stop is a loop whose callers must not have matched exhaustively. The
/// alternative is a crate-internal addition that breaks a host's build, and this crate is stable.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendBlocksError<E> {
    /// The sender could not read a block it had planned.
    #[error("the block could not be read: {0}")]
    Read(#[from] TransferError),
    /// The link refused it. The error is the caller's own type: this loop does not know what a link is.
    #[error("the block could not be sent")]
    Send(#[source] E),
}

/// Reads every unsent block and hands it to `send`, reporting progress after each.
///
/// # Errors
///
/// [`SendBlocksError`] as soon as a block cannot be read or is refused. The blocks already sent stay marked as sent, so a
/// caller that retries resumes rather than starting again — which is the whole point of [`TransferSender::mark_sent`].
pub fn send_blocks<E>(
    sender: &mut TransferSender,
    mut send: impl FnMut(u32, &[u8]) -> Result<(), E>,
    mut on_progress: impl FnMut(u32, u32),
) -> Result<(), SendBlocksError<E>> {
    let total = u32::try_from(sender.blocks().len()).unwrap_or(u32::MAX);
    for index in sender.outstanding() {
        // Read, send, mark — in that order. Marking first would record a block as delivered before the link agreed to carry
        // it, and a transfer that stalled after that would claim to have sent what the peer never saw.
        let data = sender.read_block(index)?;
        if let Err(refused) = send(index, &data) {
            return Err(SendBlocksError::Send(refused));
        }
        sender.mark_sent(index);
        on_progress(index.saturating_add(1), total);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
