//! Transport: what happens between two devices once a socket exists.
//!
//! # The split, and why it is where it is
//!
//! This crate is the first that performs IO. Everything below it — [`synra_protocol`]'s framing, envelopes and
//! handshake — is pure, and everything above it is the kernel's state machines. That leaves this crate holding
//! exactly the decisions that are about *time and failure*:
//!
//! * [`backoff`] — when to try a peer again, and how long to wait.
//! * [`liveness`] — whether an open socket is still carrying anything.
//! * [`write_queue`] — what to do when a peer stops reading.
//!
//! Those three are the whole of "the network is unreliable" as far as this crate is concerned, and none of them
//! needs a socket to be tested: each one owns no clock and performs no IO, taking the current time from the caller.
//!
//! # What is deliberately not here
//!
//! No socket type, no runtime, no UDP or mDNS listener. Those are the application layer's, because a listener's
//! shape depends on the runtime the application chose, and putting one here would make the kernel's tests need a
//! network. What is here is the part that gets the answer wrong in ways a test cannot see: an off-by-one in a
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

pub mod backoff;
pub mod liveness;
pub mod write_queue;

pub use backoff::{Backoff, BackoffRefusal, MAX_ATTEMPTS, PendingRetry, ResetReason, RetryTrigger};
pub use liveness::{DeathReason, HeartbeatAction, LinkHealth, Liveness};
pub use write_queue::{CloseReason, QueueOutcome, QueueRefusal, WriteQueue};
