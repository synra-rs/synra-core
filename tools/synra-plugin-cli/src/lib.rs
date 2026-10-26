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
//! `dev`: it needs a running host, and a version of it that only printed what it would do would be worse than one that
//! says it is not implemented.
//!
//! [`build`] and [`sign`] are here: a build shell is a compiler invocation this tool can make, and a signature is an
//! ed25519 key and a canonical form of the artifact, both of which are values rather than services.
//!
//! [`pack`] is here too: it writes the npm-shaped `.tgz` a registry serves (16 §4.1) and stops at the file, because
//! publishing is a registry's decision (an account, a scope, a policy) rather than an archive's.
//!
//! [`publish`] checks the files a static bucket would serve — index, tarball, signature — without uploading them: an
//! upload failure is the host's to report, and a published shape the installer cannot read is this tool's to prevent.

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
pub mod build;
pub mod execute;
pub mod pack;
pub mod publish;
pub mod run;
pub mod sign;
pub mod template;
pub mod upload;
pub mod verify;

pub use args::{
    BuildArgs, Cli, Command, NewArgs, PackArgs, PublishArgs, SignArgs, UploadArgs, VerifyArgs,
};
pub use build::{BuildError, BuildPlan, Step, UI_BUILD_SCRIPT, WASM_TARGET};
pub use execute::{Executed, execute, is_dry_run};
pub use pack::{pack_plugin, write_archive};
pub use publish::publish_plugin;
pub use run::{Outcome, build_plugin, new_plugin, sign_plugin, verify_plugin};
pub use sign::{SignError, SignedContent, SigningKeyFile};
pub use template::{Scaffold, ScaffoldError, ScaffoldFile, TemplateKind};
pub use upload::{UploadStep, upload_plugin};
pub use verify::{
    Finding, MAX_UI_BYTES, MAX_UI_FILES, MAX_WASM_BYTES, PROVIDED_IMPORTS, REFUSED_IMPORTS, Target,
    Verdict, VerifyReport, verify,
};
