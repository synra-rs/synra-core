//! Moving a file, once the pieces exist.
//!
//! # What was missing
//!
//! [`crate::transfer`] splits a file and checks a digest; [`crate::link`] carries blocks. Neither knows about the other, and
//! nobody was driving them — so a `TransferRequest` was never sent, a block never left memory, and a `progress` report had
//! nobody to answer it. That driving is this module, and it is the difference between "the pieces exist" and "a file moves".
//!
//! # The shape of a transfer, as the protocol defines it
//!
//! ```text
//! control plane (JSON envelopes)          data plane (ChunkFrame)
//!   file.transfer.request   ──────▶
//!   file.transfer.chunk × N ──────▶         ★ the blocks themselves
//!                           ◀────── file.transfer.progress
//!   file.transfer.complete  ──────▶
//!                           ◀────── file.transfer.complete   (the confirmation)
//! ```
//!
//! # Why the blocks are not simply written in a loop
//!
//! Because a link is not reliable and a receiver is not silent. A sender that wrote every block and then waited for one
//! acknowledgement would be one that **cannot hear a resend request until it has finished talking** — and the receiver's
//! `progress` report is the only thing that says which blocks were lost. So the sender reads between blocks: it sends a
//! window, listens for a report, and fills whatever the report says is missing. A dropped block costs a re-send; it does
//! not cost the transfer.
//!
//! # Why the digest is checked at the end and nowhere else
//!
//! Because a per-block check would tell you a block arrived, not that the file did. The one digest over the whole object is
//! what makes "the transfer succeeded" mean something, and it is checked **after** every block is in place — which is why a
//! short block, a reordered splice or a wrong byte all end at the same place: a refusal.
//! # Why this is a directory and not a file
//!
//! Because the two sides have almost nothing in common. A sender writes blocks and reads reports; a receiver writes a file
//! and reads blocks. They share a vocabulary (`types`) and a wire format (`wire`) and nothing else, and one file holding
//! both made every change to one look like a change to the other. The split is by *who is acting*, which is the only
//! division the protocol itself makes.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `types` | what a transfer reports and how it fails, used by both sides |
//! | `wire` | which messages exist and how each is built |
//! | `send` | proposing, writing blocks, and hearing what the receiver says |
//! | `receive` | accepting a proposal and deciding whether the bytes are the file |
//!
//! Everything that was public before is re-exported here, so this is a change of layout and not of interface.

pub mod receive;
pub mod send;
pub mod types;
pub mod wire;

pub use receive::{InboundProgress, Receiving, Received};
pub use send::{
    abort, await_confirmation, complete, propose, report_progress, send_blocks, send_bundle, send_file,
    WINDOW_BLOCKS,
};
pub use types::{SessionError, SessionEvent};
pub use wire::{Message, classify};

#[cfg(test)]
mod tests;
