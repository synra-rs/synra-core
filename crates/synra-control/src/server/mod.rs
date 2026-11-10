//! What the kernel does when a client asks it something.
//!
//! # Why this is a trait here rather than a method on the daemon
//!
//! A command handler that read a socket, called a kernel and wrote a socket would be one whose tests needed all three.
//! Splitting it means the *protocol* half — which requests are answered, in what order, and how a failure becomes a
//! response — is testable against a fake kernel, and the daemon supplies the real one.
//!
//! That split is where the interesting bugs live. A handler that answered a second request before the first would
//! reorder a script's output; one that answered after the client had gone would write to a closed socket; one that let a
//! failure end the connection would make every subsequent request in a pipeline fail with a framing error rather than
//! its own answer.
//!
//! # What is deliberately not here
//!
//! No sockets, no threads and no async. [`Server`] takes bytes and produces bytes, so its tests are a few lines each
//! and do not flake.

mod connection;
mod kernel;
mod refusal;

pub use connection::{Server, SessionState};
pub use kernel::Kernel;
pub use refusal::Refusal;

#[cfg(test)]
mod tests;
