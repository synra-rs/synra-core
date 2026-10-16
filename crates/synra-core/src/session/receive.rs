//! Receiving a file: the side that decides whether the bytes are the file.
//!
//! # Why the digest is checked here and nowhere else
//!
//! Because a per-block check would tell you a block arrived, not that the file did. The one digest over the whole object is
//! what makes "the transfer succeeded" mean something, and it is checked **after** every block is in place — which is why a
//! short block, a reordered splice or a wrong byte all end at the same place: a refusal.

use std::path::{Path, PathBuf};

use synra_protocol::envelope::Envelope;
use synra_protocol::ids::{TraceId, TransferId};
use synra_protocol::session::{TransferAbort, TransferAbortReason, TransferComplete, TransferRequest};

use crate::link::{Inbound, LinkError, PeerLink};
use crate::transfer::{ObjectDigest, TransferError, TransferReceiver};

use super::types::SessionError;
use super::wire::{Message, classify, envelope_for, payload_of};

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
    /// Which plugin this bundle belongs to, when it is one.
    ///
    /// ★ **Why the receiver holds this and `Decision::Finished` carries it.**
    ///
    /// The transfer path sees bytes. `Decision::Finished { path, byte_length }` says the same sentence about a screenshot
    /// and about a plugin bundle, and its only consumer prints that sentence — so "the thing that arrived is a plugin
    /// bundle" was a fact the code did not hold anywhere. `proposed_name`'s own comment admits it: *"a plugin bundle is
    /// not something this kernel installs yet"*.
    ///
    /// The field is here because **accepting the proposal** is when this is knowable — the metadata carries it. At
    /// completion the only thing left is a path, and a path is a file name.
    bundle: Option<synra_protocol::ids::PluginId>,
}

impl std::fmt::Debug for Receiving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiving")
            .field("transfer_id", &self.receiver.transfer_id())
            .field("received", &self.receiver.received_count())
            .field("bundle", &self.bundle.as_ref().map(ToString::to_string))
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
        // Read here rather than at completion, which is the whole point of the field: by then the metadata is gone and
        // the only thing left is where the bytes landed.
        let bundle = match &request.meta {
            synra_protocol::session::TransferMeta::PluginBundle { plugin_id, .. } => {
                Some(plugin_id.clone())
            }
            _ => None,
        };
        let receiver = TransferReceiver::accept(&request, destination)?;
        Ok(Self { receiver, trace_id, bundle })
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

    /// Which plugin this bundle belongs to, when it is one.
    #[must_use]
    pub const fn bundle(&self) -> Option<&synra_protocol::ids::PluginId> {
        self.bundle.as_ref()
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
