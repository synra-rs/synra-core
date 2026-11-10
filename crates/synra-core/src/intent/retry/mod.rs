//! When an unanswered dispatch is sent again.
//!
//! # Why this is in the kernel and not in one host
//!
//! Because the window and the daemon both leave `Dispatching` intents behind when they stop, and both need the same
//! answer to "when is the next try": a schedule that survives a restart, grows with each failure, and stops at a bound. The
//! window had this first; the daemon's one-shot resend (19 §8.224) was the evidence that a second copy would be written if
//! it stayed there. The queue is a value — no threads, no sockets, no clock — so a test moves milliseconds instead of
//! waiting five minutes.
//!
//! # What it deliberately does not do
//!
//! It does not send anything, persist anything, or tell the interface. [`RetryQueue::row`] is the row a host writes and
//! [`RetryQueue::status`] is the sentence a host shows; which link to dial and which event to emit stay with the caller.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use synra_protocol::ids::IntentId;

use crate::supervisor::{Cancellation, RestartPolicy, TaskId};

mod queue;
mod runner;
mod types;

pub use runner::*;
pub use types::*;

#[cfg(test)]
mod tests;
