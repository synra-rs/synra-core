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

/// Which plugin a proposal is a bundle for, when it is one.
///
/// ★ **A free function rather than a match inside [`Receiving::accept`], so that it can be tested.**
///
/// Accepting needs a whole envelope and a writable destination, and a test for "does a bundle carry its plugin" would
/// have to build both — a `TransferRequest` with a real digest, an envelope around it, a temporary directory. The
/// decision itself reads one field of the metadata, so it takes the metadata and nothing else. That is the same narrowing
/// that made the disk probe testable: a pure question should not need a filesystem to answer.
#[must_use]
pub fn bundle_of(meta: &synra_protocol::session::TransferMeta) -> Option<synra_protocol::ids::PluginId> {
    match meta {
        synra_protocol::session::TransferMeta::PluginBundle { plugin_id, .. } => Some(plugin_id.clone()),
        _ => None,
    }
}

/// A receiver's side of one transfer.
    /// Which version a proposal declares, when it is a bundle.
///
/// Beside [`bundle_of`] and for the same reason: this is one field of the metadata, and a pure question should not need
/// an envelope and a writable directory to answer.
#[must_use]
pub fn version_of(meta: &synra_protocol::session::TransferMeta) -> Option<String> {
    match meta {
        synra_protocol::session::TransferMeta::PluginBundle { version, .. } => Some(version.clone()),
        _ => None,
    }
}

/// A receiver's side of one transfer.
///
/// ★ Its `version` and `bundle` are read out of the proposal's metadata at acceptance, because that is where the
/// sender's declaration lives — and by the time the transfer finishes, all that is left is a path.
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
    /// Which round this transfer belongs to, when it belongs to one.
    ///
    /// ★ The value the *sender* chose (round 166), carried so the receiver can name the round in the result it sends
    /// back. Read out of the request rather than made up here: a receiver that invented one would answer with a round
    /// the sender has never heard of.
    sync_session_id: Option<synra_protocol::ids::SessionId>,
    /// The request this transfer answered.
    ///
    /// ★ Carried because a result has to reply *to* something: `messaging::sync_result` needs the request, and a reply
    /// that named no request would be a message the sender cannot match to the round it started.
    request_id: synra_protocol::ids::RequestId,
    /// The version the sender declared, when this is a bundle.
    version: Option<String>,
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

/// What one inbound transfer has done so far.
///
/// # Why this is a value rather than a callback into the receiver
///
/// Because the place that reports progress is not the place that holds the receiver: the listener reads decisions, and a
/// decision is a value. A reporter that reached back into `Receiving` would have to keep it alive past the arm that
/// consumed it, which is exactly the shape that makes a progress bar freeze when a transfer ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundProgress {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// What the file will be called, as the sender proposed it.
    pub file_name: String,
    /// Which plugin it is a bundle for, when it is one.
    pub bundle: Option<synra_protocol::ids::PluginId>,
    /// How many bytes have arrived.
    pub received_bytes: u64,
    /// How many there are.
    pub total_bytes: u64,
    /// How many blocks are held.
    pub blocks_done: u32,
    /// How many there are.
    pub blocks_total: u32,
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
        let bundle = bundle_of(&request.meta);
        let request_id = envelope.request_id;
        let sync_session_id = request.sync_session_id;
        let version = version_of(&request.meta);
        let receiver = TransferReceiver::accept(&request, destination)?;
        Ok(Self {
            receiver,
            trace_id,
            bundle,
            version,
            request_id,
            sync_session_id,
        })
    }

    /// The numbers a progress reporter needs, taken while the receiver is still here.
    #[must_use]
    pub fn progress(&self) -> InboundProgress {
        InboundProgress {
            transfer_id: self.receiver.transfer_id(),
            file_name: self
                .receiver
                .path()
                .file_name()
                .map_or_else(|| "file".to_owned(), |name| name.to_string_lossy().into_owned()),
            bundle: self.bundle.clone(),
            received_bytes: self.receiver.bytes_received(),
            total_bytes: self.receiver.byte_length(),
            blocks_done: self.receiver.received_count(),
            blocks_total: self.receiver.bitmap().total_blocks(),
        }
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

    /// The version the sender declared, when this is a bundle.
    #[must_use]
    pub const fn version(&self) -> Option<&String> {
        self.version.as_ref()
    }

    /// The request this transfer answered.
    #[must_use]
    pub const fn request_id(&self) -> synra_protocol::ids::RequestId {
        self.request_id
    }

    /// Which round this transfer belongs to, when it belongs to one.
    #[must_use]
    pub const fn sync_session_id(&self) -> Option<synra_protocol::ids::SessionId> {
        self.sync_session_id
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

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::ids::PluginId;
    use synra_protocol::session::TransferMeta;

    fn a_plugin_id() -> PluginId {
        PluginId::try_from("@acme/chat".to_owned()).expect("a plugin id")
    }

    #[test]
    fn a_bundle_proposal_names_its_plugin() {
        // ★ 这条测试是第 139 轮欠下的。那一轮把 `bundle` 加进了结构、让 `Decision::Finished` 带上它、
        // 让 listener 说得出来 —— 但没有一条测试说过「插件包带着它的 plugin_id」这句话。
        let meta = TransferMeta::PluginBundle { plugin_id: a_plugin_id(), version: "1.2.0".to_owned() };

        assert_eq!(bundle_of(&meta), Some(a_plugin_id()));
    }

    #[test]
    fn an_attachment_proposal_names_no_plugin() {
        // 另一半，而且是没有它时最容易出的错：把所有传输都当成包。
        let meta = TransferMeta::Attachment {
            file_name: "notes.txt".to_owned(),
            mime_type: None,
            context_id: None,
        };

        assert_eq!(bundle_of(&meta), None);
    }
}
