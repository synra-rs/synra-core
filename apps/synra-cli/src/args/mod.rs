//! The command surface: what a user types, and what it means.
//!
//! # Why the parser is a value
//!
//! The command line is a contract with a person, and the failures it produces are the ones a person reads: a missing
//! flag, an unknown subcommand, two flags that contradict each other. Every one of those is decidable from the
//! arguments alone, so putting them in a type worth testing means the failures are tested rather than discovered by
//! whoever types the command wrong.
//!
//! It is also what keeps `main.rs` short. The design document requires it to be at most sixty lines with the logic in
//! this crate's library, because a `main` that grew would be a `main` that holds the one part of a CLI nobody writes
//! tests for.
//!
//! # Flags that contradict each other are refused
//!
//! `send --text "hi" --file a.txt` is not "one of them wins". It is a user who meant one thing and typed two, and
//! guessing produces a message that goes somewhere they did not intend. `clap`'s `conflicts_with` makes it an error
//! with both flags in the message.
//!
//! # The subcommands mirror the kernel's aggregates
//!
//! `devices`, `status`, `send`, `plugin`, `logs`, `doctor`, `db`. Not one command per Tauri command — the interface
//! has forty because it drives every screen, and a person on a terminal wants seven. The mapping is the aggregate,
//! which is why a new kernel feature tends to land inside an existing group rather than adding a command.

mod common;
mod misc;
mod plugins;

pub use common::*;
pub use misc::*;
pub use plugins::*;

#[cfg(test)]
mod tests;

