use std::path::PathBuf;

use synra_protocol::ids::{TraceId, TransferId};
use synra_protocol::session::TransferAbortReason;

use crate::transfer::TransferReceiver;

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
pub fn bundle_of(
    meta: &synra_protocol::session::TransferMeta,
) -> Option<synra_protocol::ids::PluginId> {
    match meta {
        synra_protocol::session::TransferMeta::PluginBundle { plugin_id, .. } => {
            Some(plugin_id.clone())
        }
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
        synra_protocol::session::TransferMeta::PluginBundle { version, .. } => {
            Some(version.clone())
        }
        _ => None,
    }
}

/// A receiver's side of one transfer.
///
/// ★ Its `version` and `bundle` are read out of the proposal's metadata at acceptance, because that is where the
/// sender's declaration lives — and by the time the transfer finishes, all that is left is a path.
pub struct Receiving {
    /// The transfer being filled.
    pub(super) receiver: TransferReceiver,
    /// The trace this transfer's messages share.
    pub(super) trace_id: TraceId,
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
    pub(super) bundle: Option<synra_protocol::ids::PluginId>,
    /// Which round this transfer belongs to, when it belongs to one.
    ///
    /// ★ The value the *sender* chose (round 166), carried so the receiver can name the round in the result it sends
    /// back. Read out of the request rather than made up here: a receiver that invented one would answer with a round
    /// the sender has never heard of.
    pub(super) sync_session_id: Option<synra_protocol::ids::SessionId>,
    /// The request this transfer answered.
    ///
    /// ★ Carried because a result has to reply *to* something: `messaging::sync_result` needs the request, and a reply
    /// that named no request would be a message the sender cannot match to the round it started.
    pub(super) request_id: synra_protocol::ids::RequestId,
    /// The version the sender declared, when this is a bundle.
    pub(super) version: Option<String>,
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
