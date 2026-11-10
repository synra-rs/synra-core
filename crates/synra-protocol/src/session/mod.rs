//! Session payloads: pairing, intent and transfer.
//!
//! A session is a conversation with a beginning and an end, and the thing that most often goes wrong
//! in one is that it never ends. A pairing request whose answer is lost, an intent whose peer was
//! suspended mid-flight, a transfer interrupted by a laptop closing — each leaves the initiator
//! waiting forever unless something bounds it.
//!
//! So every session has a timeout, and they live in one place: [`SessionTimeouts`].
//!
//! # Why the initiator must time itself out
//!
//! Every payload here is *also* protected by the peer's own timeout, and that is not enough. If the
//! only timeout is on the receiving side, an initiator whose packet was dropped before it arrived
//! waits for an answer that was never coming — no error, no log, just a spinner. Each side bounds
//! its own wait independently.

mod pairing;
mod state;
mod transfer;

pub use pairing::{IntentDisplay, IntentInvocation, IntentOutcome, PeerProfile, PlatformKind, SessionTimeouts};
pub use state::{OutstandingRequests, PeerSnapshot, SessionState};
pub use transfer::{
    DigestAlgorithm, PluginList, PluginSummary, ProgressBitmap, SriDigest, TransferAbort,
    TransferAbortReason, TransferComplete, TransferKind, TransferMeta, TransferProgress, TransferRequest,
    TransferWindow,
};

#[cfg(test)]
mod tests;
