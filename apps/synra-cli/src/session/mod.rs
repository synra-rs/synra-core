//! Where the kernel's data lives, and what each command does.
//!
//! # Why this is not in `main`
//!
//! The design document caps `main.rs` at sixty lines of code, and the reason is not brevity. `main` is the one file in
//! a program that nobody writes tests for, so every decision that *can* be tested is moved here: where the data
//! directory is, what a command does with no kernel reachable, and what the process should exit with.
//!
//! What is left in `main` is the three things that need a process — read the arguments, call [`dispatch`], return the
//! code — and those are short enough to read in one go.
//!
//! # The data root has one answer
//!
//! `synra doctor` checks the directories the kernel would actually use, so the two have to agree about where those
//! are. A `doctor` that probed a directory nobody uses would report a healthy installation on a machine whose real
//! one is broken, which is the worst possible answer from a diagnostic tool.
//!
//! The environment variable is the answer for now: `SYNRA_DATA_DIR` if it is set, and a directory under the system's
//! temporary location otherwise. It is deliberately **not** an XDG-style lookup yet, because a lookup needs the
//! platform abstraction and this crate has no dependency on it — the daemon owns that decision, and duplicating it
//! here is how the two would come to disagree.

mod commands;
mod data;
mod doctor;

pub use commands::{dispatch, follow, follow_in};
pub use data::{data_root, data_root_from, CommandOutcome, DATA_DIR_VAR};
pub(crate) use doctor::doctor_outcome;

// `no_kernel` used to live here: every command but `doctor` printed "no kernel is reachable". It is gone because the
// commands now open the socket, and the sentence a user needs is the one the socket error carries — which names the
// **path the client looked at**. A generic message hid the commonest cause, which is that the client looked in the wrong
// place.

#[cfg(test)]
mod tests;
