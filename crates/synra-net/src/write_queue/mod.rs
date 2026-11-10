//! The write queue: bounded, and honest about overflowing.
//!
//! # Overflow closes the link, and that is the least bad option
//!
//! A queue exists so a slow peer does not block the caller. It is bounded because an unbounded one is a memory leak
//! with a friendly name — a peer that stops reading turns the application into a buffer. So when the bound is
//! reached, one of three things has to happen:
//!
//! * **Drop the oldest.** Breaks ordering, which for a transfer means the receiver assembles a file from chunks
//!   that no longer correspond to the sender's view of it. Silent corruption.
//! * **Drop the newest.** Loses whatever the caller just handed over. The caller believes it was queued, so nothing
//!   retries.
//! * **Close the link.** Every frame the caller queued is lost, and the caller is *told* — reconnection happens
//!   against a peer that will re-request what it still needs.
//!
//! The design document picks the third, and the reason is the one above: it is the only option where the loss is
//! visible. The cost is a reconnect; the cost of the others is a message that vanished and a bug report that says
//! "sometimes messages do not arrive".
//!
//! # Frames are counted, not bytes
//!
//! [`WRITE_QUEUE_CAPACITY`] is a frame count. Counting bytes would let a queue of 256 small frames hold the same
//! memory as a few large ones — but frames are already bounded by [`MAX_FRAME_LEN`], so a frame count bounds the
//! memory within a factor of the largest frame, and a count is what the design document specifies.

mod queue;

pub use queue::WriteQueue;

/// Why a frame could not be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueRefusal {
    /// The queue is full, so the link must be closed.
    ///
    /// Not an error the caller recovers from by retrying: the link is ending, and the caller's next step is to wait
    /// for the reconnection and re-request. Retrying against a full queue would spin.
    Full {
        /// How many frames were already queued.
        queued: usize,
        /// The bound.
        capacity: usize,
    },
    /// The link is already closed.
    Closed {
        /// Why it closed.
        reason: CloseReason,
    },
}

impl QueueRefusal {
    /// Whether the caller may try again later.
    ///
    /// Neither refusal is retryable against the same link, which is the point: a caller that loops on either would
    /// spin. A closed link is replaced by a new one and a full link is closed by the refusal.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        false
    }
}

/// Why a link closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// The queue overflowed.
    Overflow,
    /// The peer said goodbye.
    Goodbye,
    /// The peer refused the handshake.
    Refused,
    /// Nothing arrived within the timeout.
    Silent,
    /// The caller asked for it.
    Requested,
    /// A write failed.
    WriteFailed,
}

impl CloseReason {
    /// Whether reconnecting makes sense.
    #[must_use]
    pub const fn is_worth_reconnecting(self) -> bool {
        match self {
            Self::Overflow | Self::Silent | Self::WriteFailed | Self::Requested => true,
            // A goodbye is a decision and a refusal may be permanent, so retrying immediately races a shutdown or
            // repeats something that will not change.
            Self::Goodbye | Self::Refused => false,
        }
    }

    /// A name for a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overflow => "overflow",
            Self::Goodbye => "goodbye",
            Self::Refused => "refused",
            Self::Silent => "silent",
            Self::Requested => "requested",
            Self::WriteFailed => "write-failed",
        }
    }
}

/// What happened when a frame was added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueOutcome {
    /// It was queued.
    Queued,
    /// It was queued and the queue is now congested.
    ///
    /// Reported so the caller can slow down, or so the interface can show that a peer is behind. Not a failure: a
    /// burst is ordinary.
    QueuedCongested {
        /// How full the queue is, as a percentage.
        queue_percent: u8,
    },
    /// The queue was full, so the link is now closed.
    Overflowed {
        /// How many frames were queued when it happened.
        queued: usize,
        /// How many were discarded.
        discarded: usize,
    },
}

impl QueueOutcome {
    /// Whether the link survived.
    #[must_use]
    pub const fn link_survived(self) -> bool {
        !matches!(self, Self::Overflowed { .. })
    }
}

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
