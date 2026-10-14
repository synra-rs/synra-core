//! Intent routing: what a user asked for, who could do it, and what actually happened.
//!
//! # Why this is a directory
//!
//! Because it holds two separable things with different readers. [`types`] is the **vocabulary** — a source, a
//! candidate, every way an intent can end — and it is what somebody adding a new way to raise an intent reads.
//! [`board`] is the **sequencing** — matching windows, idempotency, what a candidate may become — and it is what
//! somebody changing the order things happen in reads.
//!
//! One file held both for a while and the effect was that a change to the vocabulary meant scrolling past four hundred
//! lines of state machine to find it.
//!
//! # The shape of the whole thing
//!
//! ```text
//!   raise ──▶ Matching ──(deadline)──▶ Choosing ──(user)──▶ Confirming ──(user)──▶ Dispatching
//!                 │                       │                                            │
//!                 │                       └──────────(one candidate, automatic)─────────┤
//!                 │                                                                    │
//!                 └──(nothing claimed it)──▶ NoHandler                       Succeeded / Failed
//! ```
//!
//! Four of those arrows are a decision about a *person*: whether to interrupt them, what to show them, and whether
//! their answer is still about the same thing. That is why the states are separate rather than one `Pending` with
//! flags.
//!
//! # What is deliberately not here
//!
//! No plugins are called and no messages are sent. [`Board::settle`] decides *that* matching is over; the caller is
//! what has a runtime and a plugin host. Keeping the decision a value is what makes the sequence testable without a
//! clock, a socket or a guest — and the sequence is where the bugs are, not the plumbing.

pub mod board;
pub mod types;

#[cfg(test)]
mod tests;

pub use board::{Board, CandidateChoice, ENDED_MEMORY, MATCHING_WINDOW, Raised};
pub use types::{
    Choice, Intent, IntentCandidate, IntentError, IntentSource, IntentState, PlannedAction,
};
