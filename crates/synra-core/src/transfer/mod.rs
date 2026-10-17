//! Sending a file, in pieces, and knowing whether it arrived.
//!
//! # What this layer owns, and what it does not
//!
//! The protocol already defines the wire shapes — `TransferRequest`, `ProgressBitmap`, `SriDigest`, the chunk frame — and
//! `synra-protocol` is tested against them. What nobody had was the part that *uses* them: how a file becomes ordered
//! pieces, what a receiver does with a piece that arrives twice or not at all, and how either side decides the object
//! arrived intact.
//!
//! That is this module, and it deliberately holds no socket. Every decision here is a value in and a value out, which is
//! what makes the interesting cases — a re-sent block, a block from a transfer that was never proposed, a digest that
//! disagrees — testable without a network at all. [`TransferSender`] and [`TransferReceiver`] are driven by a caller that
//! owns a link.
//!
//! # The two rules everything follows
//!
//! * **The digest is the only proof.** A receiver that accepted a file because every block arrived would be one that
//!   accepts a file whose blocks arrived *wrong* — a reordered splice, a truncated tail, a disk that lied. The whole-object
//!   digest is checked once, at the end, and nothing counts as received until it agrees.
//! * **A transfer is identified, not inferred.** `transfer_id` is in the request and in every frame, so a block that
//!   names an unknown transfer is refused rather than applied to whatever happens to be in progress. Without that, two
//!   files sent at once interleave into one corrupt one.
//!
//! # Why the sender chunks the whole file up front
//!
//! It does not hash twice. [`TransferSender::open`] streams the file once, computing the digest and recording each block's
//! offset — so a ten-gigabyte file costs one pass and its plan, not two passes and a buffer. The alternative, hashing as
//! blocks are sent, would mean the `TransferRequest` could not carry the digest until *after* the data had moved — and the
//! request is what tells the receiver whether to accept the transfer at all.

mod digest;
mod error;
mod plan;
mod receiver;
mod send;
mod sender;

pub use digest::ObjectDigest;
pub use error::TransferError;
pub use plan::{Block, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, plan_blocks};
pub use receiver::{Absorbed, TransferReceiver};
pub use send::{SendBlocksError, send_blocks};
pub use sender::TransferSender;

#[cfg(test)]
mod tests;
