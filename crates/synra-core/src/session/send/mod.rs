//! Sending one file: what the sender proposes, sends, and waits for.
//!
//! # Why this is a directory and not a file
//!
//! Because the phases of a send are separable: the proposal and the blocks that move, the transfer bookkeeping the
//! protocol defines, the control messages that arrive in reply, and the wait at the end. In one file the control
//! reader — the part that decides whether a transfer is still alive — sat between an abort and a wait.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `blocks` | the window the sender keeps in flight, the proposal, and the blocks |
//! | `transfer` | reporting progress, completing, and aborting |
//! | `control` | what the receiver sends back, and how the sender reads it |
//! | `awaiting` | file and bundle preparation entry points |
//! | `prepared` | complete workflow, cancellation, deadlines and confirmation |

mod awaiting;
mod blocks;
mod control;
mod prepared;
mod transfer;

pub use awaiting::{describe, send_bundle, send_file};
pub use blocks::{WINDOW_BLOCKS, propose, send_blocks};
pub use prepared::{SendOptions, send_prepared};
pub use transfer::{abort, complete, report_progress};

#[cfg(test)]
mod tests;
