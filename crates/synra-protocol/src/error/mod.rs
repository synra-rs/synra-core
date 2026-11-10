//! The error model.
//!
//! Two audiences, two shapes:
//!
//! * **On the wire** an error is a [`SynraError`] — a stable [`ErrorCode`], a human message, and a
//!   list of actions the user could take. It is serialisable and it is what a peer receives.
//! * **Inside a process** the same type is used, so there is no translation layer whose mapping can
//!   drift.
//!
//! # Why codes, not strings
//!
//! Callers branch on [`ErrorCode`]. Branching on the message would look like a shortcut and behave
//! like a trap: the message text changes with platform and with dependency version, and a real
//! error that happens to contain a keyword gets silently reclassified. `UserVisibility` exists for
//! the same reason — whether the user should see something is a property of the *kind* of failure,
//! decided by the type, not by matching substrings.

mod code;
mod report;

pub use code::ErrorCode;
pub use report::{SuggestedAction, SynraError, UserVisibility};

#[cfg(test)]
mod tests;
