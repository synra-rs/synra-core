//! Transport: what happens between two devices once a socket exists.
//!
//! # The split, and why it is where it is
//!
//! This crate is the first that performs IO. Everything below it — [`synra_protocol`]'s framing, envelopes and
//! handshake — is pure, and everything above it is the kernel's state machines. That leaves this crate holding
//! the authenticated socket boundary and decisions about time and failure:
//!
//! * [`authentication`] — prove possession of an approved device key before exposing a stream.
//! * [`backoff`] — when to try a peer again, and how long to wait.
//! * [`liveness`] — whether an open socket is still carrying anything.
//! * [`write_queue`] — what to do when a peer stops reading.
//!
//! The scheduling state machines own no clock and perform no IO, taking the current time from the caller.
//! Authentication uses real sockets and a bounded monotonic handshake deadline.
//!
//! # What is deliberately not here
//!
//! No async runtime, UDP or mDNS listener. Listening and discovery belong to the application layer;
//! authentication takes ownership of an already connected TCP socket. What is here includes an off-by-one in a
//! backoff, a timeout that fires on one lost packet, an overflow that loses a message silently.
//!
//! # The three failures this crate exists to prevent
//!
//! * **Retrying in a tight loop.** A peer that is merely asleep becomes a peer whose network is saturated.
//! * **Never noticing a dead link.** An unplugged cable does not close a TCP socket, so an application that only
//!   waits on reads waits forever.
//! * **Losing a message quietly.** A queue that drops to stay bounded turns a slow peer into a missing message.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod authentication;
pub mod backoff;
pub mod liveness;
pub mod write_queue;

pub use backoff::{Backoff, BackoffRefusal, MAX_ATTEMPTS, PendingRetry, ResetReason, RetryTrigger};
pub use liveness::{DeathReason, HeartbeatAction, LinkHealth, Liveness};
pub use write_queue::{CloseReason, QueueOutcome, QueueRefusal, WriteQueue};
