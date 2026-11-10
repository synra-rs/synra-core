//! What the kernel sends to a peer, and the envelope it travels in.
//!
//! # Why this is separate from `host`
//!
//! [`crate::host::Host`] answers *who can I reach and how*; this answers *what do I say*. The two are separate because the
//! second is where the wire format lives, and a change to what a message contains should not be a change to how a
//! connection is made.
//!
//! # Why the text goes as a clipboard event
//!
//! Because that is the protocol's own answer: the built-in event for "text arrived from a peer" is
//! `_synra.clipboard.received`, and its payload is `{ text?, mime, fromDeviceId }`. There is no separate "send text"
//! event, and inventing one would be a second way to say the same thing — which is a second thing for a receiver to
//! understand and a second place for the two to disagree.
//!
//! The `mime` is `text/plain` because that is what `--text` is. The `fromDeviceId` is carried in the payload **as well as**
//! in the envelope's `from`, which looks redundant and is not: the payload is what a plugin reads, and a plugin is handed
//! a payload rather than an envelope. The envelope's field is what the link checks; the payload's is what the receiver's
//! code uses.
//!
//! # Why the size is checked here
//!
//! Because the protocol refuses an over-long payload when the envelope is built, and a refusal after a socket has been
//! dialled has already cost a handshake. Checking first means a user who pasted something enormous is told so without the
//! kernel talking to the network at all.

mod pairing;
mod plugin;
mod text;

pub use pairing::{pair_cancel, pair_request, pair_response};
pub use plugin::{plugin_list_request, plugin_list_response, sync_result, SyncResult};
pub use text::{text_from, text_to, ClipboardText, MessageError, TEXT_MIME};

#[cfg(test)]
mod tests;
