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
//! | `awaiting` | waiting for confirmation, sending a whole file, and describing a digest |

mod blocks;
mod transfer;
mod control;
mod awaiting;

pub use awaiting::{await_confirmation, await_result, describe, send_bundle, send_file};
pub use blocks::{WINDOW_BLOCKS, propose, send_blocks};
pub use transfer::{abort, complete, report_progress};

// The control reader is crate-visible: the receive half and the tests use it, but it is not part of this module's
// surface.
