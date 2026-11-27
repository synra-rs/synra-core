//! Host-facing transfer facts derived from worker observations.

use synra_protocol::session::TransferAbortReason;

use crate::link::LinkError;
use crate::session::SessionError;

use super::TransferError;

/// Progress confirmed by the receiver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcknowledgedProgress {
    /// Object bytes accepted by the receiver.
    pub bytes: u64,
    /// Distinct blocks accepted by the receiver.
    pub blocks: u32,
}

/// The stable failure category a host can share with a transfer's owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferFailure {
    /// The peer could not be reached or the connection closed.
    Connection,
    /// The transfer ran out of time.
    TimedOut,
    /// The authenticated link's grant was revoked or could no longer be checked.
    Authorization,
    /// A peer rejected the transfer or reported a local problem.
    PeerAborted(TransferAbortReason),
    /// The local file could not be read or written.
    FileIo,
    /// Object integrity could not be established.
    Integrity,
    /// The messages did not satisfy the transfer protocol.
    Protocol,
    /// The host could not launch the worker.
    WorkerUnavailable,
}

/// The result confirmed by the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    /// The receiver verified the complete object.
    Completed,
    /// The transfer stopped with a known failure.
    Failed(TransferFailure),
    /// Either side stopped the transfer before confirmation.
    Cancelled,
}

impl From<&SessionError> for TransferOutcome {
    fn from(error: &SessionError) -> Self {
        let failure = match error {
            SessionError::Cancelled
            | SessionError::Aborted {
                reason: TransferAbortReason::UserCancelled,
            } => {
                return Self::Cancelled;
            }
            SessionError::TimedOut | SessionError::Link(LinkError::TimedOut) => {
                TransferFailure::TimedOut
            }
            SessionError::Link(LinkError::Transport { .. } | LinkError::Closed) => {
                TransferFailure::Connection
            }
            SessionError::Link(
                LinkError::Unauthorized | LinkError::AuthorizationUnavailable { .. },
            ) => TransferFailure::Authorization,
            SessionError::Aborted { reason } => TransferFailure::PeerAborted(*reason),
            SessionError::Transfer(TransferError::Read { .. } | TransferError::Write { .. }) => {
                TransferFailure::FileIo
            }
            SessionError::Transfer(
                TransferError::DigestMismatch { .. } | TransferError::CompletionMismatch { .. },
            ) => TransferFailure::Integrity,
            SessionError::Link(_)
            | SessionError::Transfer(_)
            | SessionError::Event(_)
            | SessionError::Envelope(_)
            | SessionError::Payload { .. }
            | SessionError::WrongTransfer { .. }
            | SessionError::BadProgress(_)
            | SessionError::Incomplete { .. } => TransferFailure::Protocol,
        };
        Self::Failed(failure)
    }
}

/// The lifecycle of a host transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// The host accepted the transfer and is waiting for a link or peer.
    Queued,
    /// The sender and receiver are exchanging or verifying blocks.
    Transferring,
    /// The worker stopped and the result is immutable.
    Finished {
        /// How it ended.
        outcome: TransferOutcome,
        /// Host time when the outcome was recorded, in Unix milliseconds.
        at_ms: u64,
    },
}

/// Records changes once, advancing a revision only when an observation changes the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferLifecycle {
    state: TransferState,
    progress: AcknowledgedProgress,
    total: AcknowledgedProgress,
    revision: u64,
}

impl TransferLifecycle {
    /// Builds the initial record with no blocks confirmed.
    #[must_use]
    pub fn new(total: AcknowledgedProgress) -> Self {
        Self {
            state: TransferState::Queued,
            progress: AcknowledgedProgress::default(),
            total,
            revision: 0,
        }
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> TransferState {
        self.state
    }

    /// The acknowledged counts.
    #[must_use]
    pub const fn progress(&self) -> AcknowledgedProgress {
        self.progress
    }

    /// The planned counts.
    #[must_use]
    pub const fn total(&self) -> AcknowledgedProgress {
        self.total
    }

    /// The latest revision of this record.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Marks a queued transfer as started. Returns whether the record changed.
    pub fn start(&mut self) -> bool {
        if self.state != TransferState::Queued {
            return false;
        }
        self.state = TransferState::Transferring;
        self.revision += 1;
        true
    }

    /// Records a new cumulative acknowledgement, rejecting duplicates, regressions and impossible totals.
    pub fn acknowledge(&mut self, progress: AcknowledgedProgress) -> bool {
        if self.state != TransferState::Transferring
            || progress.bytes < self.progress.bytes
            || progress.blocks <= self.progress.blocks
            || progress.bytes > self.total.bytes
            || progress.blocks > self.total.blocks
        {
            return false;
        }
        self.progress = progress;
        self.revision += 1;
        true
    }

    /// Commits the first outcome. A confirmed completion accounts for the entire object.
    pub fn finish(&mut self, outcome: TransferOutcome, at_ms: u64) -> bool {
        if matches!(self.state, TransferState::Finished { .. }) {
            return false;
        }
        if outcome == TransferOutcome::Completed {
            if self.state != TransferState::Transferring {
                return false;
            }
            self.progress = self.total;
        }
        self.state = TransferState::Finished { outcome, at_ms };
        self.revision += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AcknowledgedProgress, TransferFailure, TransferLifecycle, TransferOutcome, TransferState,
    };
    use crate::{LinkError, SessionError};
    use synra_protocol::session::TransferAbortReason;

    fn counts(bytes: u64, blocks: u32) -> AcknowledgedProgress {
        AcknowledgedProgress { bytes, blocks }
    }

    #[test]
    fn counts_and_revision_follow_only_new_acknowledgements() {
        let mut lifecycle = TransferLifecycle::new(counts(100, 4));
        assert!(!lifecycle.acknowledge(counts(20, 1)));
        assert!(lifecycle.start());
        assert!(!lifecycle.start());
        assert!(lifecycle.acknowledge(counts(20, 1)));
        assert!(!lifecycle.acknowledge(counts(20, 1)));
        assert!(!lifecycle.acknowledge(counts(19, 2)));
        assert!(!lifecycle.acknowledge(counts(101, 4)));
        assert_eq!(lifecycle.revision(), 2);
        assert_eq!(lifecycle.progress(), counts(20, 1));
    }

    #[test]
    fn terminal_result_cannot_be_replaced_by_cancellation_or_late_progress() {
        let mut lifecycle = TransferLifecycle::new(counts(100, 4));
        let failure = TransferOutcome::Failed(TransferFailure::Connection);
        assert!(lifecycle.start());
        assert!(lifecycle.acknowledge(counts(20, 1)));
        assert!(lifecycle.finish(failure, 2));
        assert!(!lifecycle.finish(TransferOutcome::Cancelled, 3));
        assert!(!lifecycle.acknowledge(counts(50, 2)));
        assert!(!lifecycle.start());
        assert_eq!(
            lifecycle.state(),
            TransferState::Finished {
                outcome: failure,
                at_ms: 2
            }
        );
        assert_eq!(lifecycle.progress(), counts(20, 1));
        assert_eq!(lifecycle.revision(), 3);
    }

    #[test]
    fn confirmation_accounts_for_all_blocks_including_an_empty_file() {
        let mut lifecycle = TransferLifecycle::new(counts(0, 1));
        assert!(!lifecycle.finish(TransferOutcome::Completed, 0));
        assert!(lifecycle.start());
        assert!(lifecycle.finish(TransferOutcome::Completed, 1));
        assert_eq!(lifecycle.progress(), counts(0, 1));
    }

    #[test]
    fn session_outcomes_keep_disconnect_cancel_and_peer_refusal_distinct() {
        let terminal = TransferOutcome::from(&SessionError::Link(LinkError::Closed));
        assert_eq!(
            terminal,
            TransferOutcome::Failed(TransferFailure::Connection)
        );
        assert_eq!(
            TransferOutcome::from(&SessionError::Aborted {
                reason: TransferAbortReason::UserCancelled
            }),
            TransferOutcome::Cancelled
        );
        assert_eq!(
            TransferOutcome::from(&SessionError::Aborted {
                reason: TransferAbortReason::TooLarge
            }),
            TransferOutcome::Failed(TransferFailure::PeerAborted(TransferAbortReason::TooLarge))
        );
    }
}
