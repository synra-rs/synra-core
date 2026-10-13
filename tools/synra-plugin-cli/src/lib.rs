//! The plugin author's tool.
//!
//! # What it is for
//!
//! A plugin author works outside this repository, against a published SDK, and the failure they cannot diagnose is the
//! one that appears when their plugin reaches a user. So this tool exists to move every check earlier: the scaffold
//! produces a manifest the kernel's own validator accepts, and `verify` makes the same checks the kernel makes at
//! install time — while the author still has the source in front of them.
//!
//! # The library does the work, `main` does the I/O
//!
//! The design document caps `main.rs` at sixty lines of code, and the reason is not brevity. `main` is the one file
//! nobody writes tests for, so every decision lives here:
//!
//! * [`template`] — what `new` writes, as values rather than as a directory of files. A template kept as files is
//!   tested by nothing, and the only way to learn that one stopped compiling is for an author to report it.
//! * [`verify`] — the findings, as a list. A test asserts them, a script reads them as JSON, and the prose is one
//!   rendering of one report rather than a second implementation of it.
//!
//! # What is not here yet
//!
//! `build`, `sign`, `publish` and `dev`. Each needs something this crate does not have — a compiler invocation, an
//! ed25519 key, a registry client, a running host — and a version of them that only printed what it would do would be
//! worse than one that says it is not implemented.

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
pub mod run;
pub mod template;
pub mod verify;

pub use args::{Cli, Command, NewArgs, VerifyArgs};
pub use run::{Outcome, new_plugin, verify_plugin};
pub use template::{Scaffold, ScaffoldError, ScaffoldFile, TemplateKind};
pub use verify::{
    Finding, MAX_UI_BYTES, MAX_UI_FILES, MAX_WASM_BYTES, PROVIDED_IMPORTS, REFUSED_IMPORTS, Target,
    Verdict, VerifyReport, verify,
};