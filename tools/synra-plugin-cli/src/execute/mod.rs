//! Running a decision, which is the half that touches the world.
//!
//! # Why executing lives here rather than in `main`
//!
//! The design document caps `main.rs` at sixty lines of code, and the reason is not brevity: `main` is the one file in
//! a program that nobody writes tests for. Everything a command *decides* is in [`crate::run`]; everything it *does*
//! is here, and the two are separated so the decisions can be asserted without a filesystem.
//!
//! # What is testable about executing
//!
//! Not the commands themselves — a test that ran `cargo` would be a test of the toolchain. What is testable is the
//! part that decides what to do with a result: a step that exited non-zero stops the build, an artifact that was not
//! produced is a failure even when every command succeeded, and a signature is written where the next command looks for
//! it. Those are the parts that go wrong silently.
//!
//! # A dry run never executes
//!
//! The flag is read from the arguments rather than inferred from the outcome, because a plan and a decision look the
//! same and only the flag says whether to carry it out.

use std::path::Path;

use crate::args::Cli;
use crate::run::Outcome;

/// What executing produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    /// The lines to print, after whatever ran.
    pub lines: Vec<String>,
    /// What the process should exit with.
    pub code: u8,
}

impl Executed {
    /// Lines and success.
    #[must_use]
    pub const fn ok(lines: Vec<String>) -> Self {
        Self { lines, code: 0 }
    }

    /// Lines and a failure.
    #[must_use]
    pub const fn failed(lines: Vec<String>) -> Self {
        Self { lines, code: 1 }
    }

    /// Whether it failed.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        self.code != 0
    }
}

/// Whether the command was asked to do nothing.
#[must_use]
pub const fn is_dry_run(cli: &Cli) -> bool {
    match &cli.command {
        crate::args::Command::New(args) => args.dry_run,
        crate::args::Command::Build(args) => args.dry_run,
        crate::args::Command::Pack(args) => args.dry_run,
        crate::args::Command::Upload(args) => args.dry_run,
        // Neither has a dry run: `verify` changes nothing, and a signature an author asked for is one they want. `publish`
        // only reads, so there is nothing a dry run could skip.
        crate::args::Command::Verify(_)
        | crate::args::Command::Sign(_)
        | crate::args::Command::Publish(_) => false,
    }
}

/// Carries out what a command decided.
#[must_use]
pub fn execute(outcome: &Outcome, dry_run: bool) -> Executed {
    match outcome {
        // Nothing to do: the decision *is* the answer.
        Outcome::Reported { .. } => Executed {
            lines: Vec::new(),
            code: outcome.exit_code(),
        },

        Outcome::Scaffold { root, files, .. } => {
            if dry_run {
                return Executed::ok(Vec::new());
            }
            write_files(root, files)
        }

        Outcome::Build { plan, .. } => {
            if dry_run {
                return Executed::ok(Vec::new());
            }
            run_steps(plan)
        }

        Outcome::Archive {
            target,
            manifest,
            artifacts,
            signature,
            index,
            ..
        } => {
            if dry_run {
                return Executed::ok(vec![format!("would write {}", target.display())]);
            }
            match crate::pack::write_archive(target, manifest, artifacts, signature.as_deref()) {
                Ok(()) => {
                    let mut lines = vec![format!("wrote {}", target.display())];
                    if let Some((path, body)) = index {
                        if let Some(parent) = path.parent()
                            && let Err(error) = std::fs::create_dir_all(parent)
                        {
                            return Executed::failed(vec![format!(
                                "{}: {error}",
                                parent.display()
                            )]);
                        }
                        if let Err(error) = std::fs::write(path, body) {
                            return Executed::failed(vec![format!("{}: {error}", path.display())]);
                        }
                        lines.push(format!("wrote {}", path.display()));
                    }
                    Executed::ok(lines)
                }
                Err(error) => Executed::failed(vec![error]),
            }
        }

        Outcome::Signature {
            path,
            signature,
            public,
            ..
        } => {
            // The signature and the public key beside it, so `--verify` has the one thing it needs without a second
            // command and without the author copying a key between files.
            let public_path = path.with_file_name("public-key.txt");
            let write = |target: &Path, body: String| -> Result<(), String> {
                std::fs::write(target, body)
                    .map_err(|error| format!("{}: {error}", target.display()))
            };

            if let Err(error) = write(path, format!("{signature}\n")) {
                return Executed::failed(vec![error]);
            }
            if let Err(error) = write(&public_path, format!("{public}\n")) {
                return Executed::failed(vec![error]);
            }
            Executed::ok(vec![format!(
                "wrote {} and {}",
                path.display(),
                public_path.display()
            )])
        }
    }
}

/// Writes a scaffold's files.
fn write_files(root: &Path, files: &[(String, String)]) -> Executed {
    for (relative, contents) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            return Executed::failed(vec![format!("{}: {error}", parent.display())]);
        }
        if let Err(error) = std::fs::write(&path, contents) {
            return Executed::failed(vec![format!("{}: {error}", path.display())]);
        }
    }
    Executed::ok(Vec::new())
}

/// Runs a build's commands and checks what they produced.
fn run_steps(plan: &crate::build::BuildPlan) -> Executed {
    match crate::build::bundle::run(plan) {
        Ok(lines) => Executed::ok(lines),
        Err(error) => Executed::failed(vec![error]),
    }
}

#[cfg(test)]
mod tests;
