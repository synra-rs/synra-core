//! The kernel's command-line host.
//!
//! # What it is for
//!
//! Two things, and the second is the one that matters.
//!
//! It is a **usable tool**: list the devices, send a file, manage plugins, read the log. A user on a terminal with no
//! interface installed gets the same kernel.
//!
//! And it is the **proof that the kernel needs no interface**. The
//! kernel must be usable without a window, and the way to check a claim like that is to build the thing that would
//! break if it were false. If a command here cannot work without Tauri, or needs a type the interface also defines,
//! the kernel's boundary has broken — which is why this crate shares nothing with the application but the kernel's
//! own public API.
//!
//! # Why the logic is here and `main.rs` is short
//!
//! The design document requires `main.rs` to be at most sixty lines, with a CI guard on the count. The reason is not
//! brevity: `main` is the one file in a program that nobody writes tests for, so everything decidable in a test — the
//! command surface, the doctor report, what the process exits with — lives in this library where a test can reach it.
//!
//! `main` keeps three things: read the arguments, dispatch, set the exit code. Those are the parts that cannot be
//! tested without running a process, and they are the parts that are short enough to read in one go.
//!
//! # No kernel is started here, yet
//!
//! The commands that need a link to a running kernel report that no kernel is reachable, which is an honest answer.
//! Starting one in-process is the next step, and it belongs behind the socket [`session`] describes rather than behind
//! a dependency on the application.

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

pub mod args;
pub mod channel;
pub mod db;
pub mod doctor;
pub mod session;

pub use args::{
    Cli, Command, DbAction, DbArgs, DevicesArgs, DoctorArgs, LogsArgs, OutputFormat, PairArgs,
    Payload, PayloadError, PluginAction, PluginArgs, SendArgs,
};
pub use channel::{Question, Shape, ask, outcome_of, question_for, transport_failure};
pub use doctor::{DoctorReport, HostSummary, ProbeLine};
pub use session::{CommandOutcome, DATA_DIR_VAR, data_root, data_root_from, dispatch};