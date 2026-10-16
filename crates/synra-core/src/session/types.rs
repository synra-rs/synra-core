//! The vocabulary a transfer is described in: what it reports, and how it fails.
//!
//! # Why these are not beside the code that produces them
//!
//! Because both directions use them. A `Resend` is produced by a receiver and read by a sender; a `SessionError` is
//! returned by either. Keeping them with one side would make the other side import it, which is how a module ends up with
//! two owners and no home.

use synra_protocol::envelope::EnvelopeError;
use synra_protocol::event::EventNameError;
use synra_protocol::ids::TransferId;
use synra_protocol::session::TransferAbortReason;

use crate::link::LinkError;
use crate::transfer::TransferError;

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
    /// What the receiver answered about a bundle it has finished with.
    ///
    /// ★ **Why this is an event rather than a return value.** It arrives *after* the confirmation, on the same link,
    /// and a list of events is how everything else on this link is described.
    ///
    /// ★ And it has to be **read**: `await_confirmation` stops at the receiver's `Complete`, so a result left in the
    /// stream would be the next reader's message about a round that is already over. A reply nobody reads is not an
    /// unanswered question — it is a wrong answer to the next one.
    SyncResult {
        /// What the receiver said it did.
        result: crate::messaging::SyncResult,
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
