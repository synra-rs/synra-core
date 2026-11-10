use std::path::{Path, PathBuf};

use synra_protocol::ids::{DeviceId, TraceId};
use synra_protocol::session::TransferRequest;

/// The shared item an envelope carries, when it carries one.
///
/// # ★ Why the event name is not enough
///
/// Because `_synra.clipboard.received` is how a peer's shared text arrives, and everything a plugin is asked about — the
/// text, the mime, which device sent it — is in the body. The daemon reported the name and dropped the body, so a share
/// could arrive and be announced while nothing could act on it.
///
/// # Why a body that cannot be read is `None` rather than an error
///
/// Because a peer may send a well-formed envelope this build cannot interpret, and that is not a broken link: the frame
/// was delivered, the connection is working, and there is simply nothing here to route. Returning an error would make the
/// caller close a link over a message it merely did not understand.
pub(super) fn share_of(
    envelope: &synra_protocol::envelope::Envelope,
) -> Option<synra_protocol::inbound::ShareItem> {
    if envelope.event.as_str() != synra_protocol::event::builtin::CLIPBOARD_RECEIVED {
        return None;
    }
    // ★ The device in the payload is the sender's **claim**; the envelope's own `from` is what the handshake established.
    // The claim is dropped rather than trusted, so a peer cannot attribute its share to another device.
    let text = crate::text_from(envelope).ok()?;
    Some(synra_protocol::inbound::ShareItem {
        from: envelope.from,
        mime: text.mime,
        text: Some(text.text),
        // A text message carries no transfer, and an id invented here would name a transfer that does not exist.
        transfers: Vec::new(),
        context_id: None,
    })
}

/// What a host is asked before an incoming transfer's bytes are stored.
///
/// # Why the answer is asked for before anything is written
///
/// Because "accept the file" is a decision about the user's disk, and a decision made after the bytes are already in the
/// inbox is not a decision — it is a notification. The peer's proposal names the file, its size and its kind, which is
/// everything the prompt needs and nothing that requires the bytes.
#[derive(Debug)]
pub struct Offer<'a> {
    /// The device that dialled, as the handshake established it.
    pub peer: DeviceId,
    /// Where it connected from, for the prompt and the log.
    pub peer_address: &'a str,
    /// What it said it is sending.
    pub request: &'a TransferRequest,
    /// The name the file would take, already sanitised.
    pub file_name: &'a str,
    /// Where it would land.
    pub destination: &'a Path,
}

/// What the host answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfferDecision {
    /// Store the file.
    Accept,
    /// Refuse it, and tell the peer so.
    Refuse,
}

/// What a host is asked before an incoming transfer is accepted.
pub type OfferCallback = dyn Fn(&Offer<'_>) -> OfferDecision + Send + Sync;

/// The answer for a host with nobody to ask: the behaviour every caller had before the callback existed.
#[must_use]
pub const fn auto_accept(_: &Offer<'_>) -> OfferDecision {
    OfferDecision::Accept
}

/// What to do with a message that arrived on an inbound connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// A transfer was proposed and accepted; blocks may now arrive.
    Accepted {
        /// Which transfer.
        transfer_id: String,
        /// Which file it will become.
        file_name: String,
    },
    /// A block was stored.
    Stored {
        /// Which block.
        index: u32,
        /// Whether it had already arrived.
        duplicate: bool,
    },
    /// The transfer finished and the file was verified.
    Finished {
        /// Where it is.
        path: PathBuf,
        /// How large.
        byte_length: u64,
        /// Which plugin it is a bundle for, when it is one.
        ///
        /// Carried rather than guessed from the file name: `proposed_name` builds `plugin-<id>.synra`, and a consumer
        /// that parsed that back would be wrong the first time somebody sent a file called `plugin-notes.synra`.
        bundle: Option<synra_protocol::ids::PluginId>,
        /// The trace this transfer belongs to.
        ///
        /// ★ Carried for the same reason the round is: a result is a reply, and a reply belongs to the question's
        /// trace — that is what makes a log filter able to show the whole exchange on one side or the other.
        trace_id: TraceId,
        /// Which round this transfer belongs to, so a result can name it.
        sync_session_id: Option<synra_protocol::ids::SessionId>,
        /// The request this transfer answered, so a result can reply to it.
        request_id: synra_protocol::ids::RequestId,
        /// The version the sender declared, when this is a bundle.
        version: Option<String>,
        /// The digest the receiver checked the file against.
        ///
        /// ★ Carried because it is the only thing that answers "do these two devices hold the same bytes" — the
        /// question the `sync_records` table exists for. It was already in `Received::Verified` and was being dropped
        /// by a `..` in the match below.
        digest: String,
    },
    /// The transfer ended without a usable file.
    Failed {
        /// Why.
        why: String,
    },
    /// A message for another feature, reported rather than dropped.
    ///
    /// # Why this is not `Ignored`
    ///
    /// Because "not a transfer" and "nothing to do with this connection" are different, and the difference is what a user
    /// is told. A peer that sent text has sent a message this kernel received — there is simply no event bus wired up to
    /// deliver it — and a daemon that reported neither would be one whose log looks identical whether the message arrived
    /// or was lost in the network.
    ///
    /// ★ **2026-10-18: one of those messages is now answered rather than only reported.** A peer may ask what plugins this
    /// device has, and that answer is a reply — it needs the request's id, trace and sender — so the envelope travels with
    /// the decision. It is `None` for the one case where there is no single envelope to name: an unrecognised message that
    /// arrived in the middle of a transfer, which the transfer's own reader consumed.
    Delivered {
        /// The event the message carried.
        event: String,
        /// What was shared, when the message was a share this kernel can route.
        ///
        /// ★ Why the payload travels after all.
        ///
        /// This variant carried the event's **name** alone, which was right for its original purpose — reporting that
        /// something arrived — and wrong for the one that matters: a peer's shared text is precisely what the router
        /// needs, and everything else about it (the mime, which device sent it) is in the body. A name is not enough to
        /// ask a plugin "can you handle this?", so the share was reported and dropped.
        ///
        /// `None` for a message that is not a share, and for one whose body could not be read. The two are the same to
        /// the caller: there is nothing to route.
        share: Option<synra_protocol::inbound::ShareItem>,
        /// The envelope that arrived, when it is still available to answer.
        ///
        /// ★ Why this is carried at all: `plugin_list_response` is a **reply**, and a reply needs the request's id, its
        /// trace and the address it came from. All three are in the envelope, and rebuilding them from the event's name
        /// would be inventing three facts to save a clone.
        request: Option<Box<synra_protocol::envelope::Envelope>>,
    },
    /// A message this connection has nothing to do with.
    Ignored,
    /// Nothing arrived and the wait is over, so the connection has nothing more to say.
    ///
    /// # Why this is not `Failed`
    ///
    /// Because a peer that has gone quiet has not done anything wrong, and a transfer that is mid-flight has a
    /// `receiving` in progress — so this is only reached when there is **no** transfer. Treating it as a failure would
    /// report every idle connection as a fault, and treating it as `Ignored` would make the caller loop for ever.
    Idle,
}
