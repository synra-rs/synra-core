//! What the commands do, as values rather than as printed output.
//!
//! # Why this is not in `main`
//!
//! The design document caps `main.rs` at sixty lines of code, and the reason is not brevity: `main` is the one file in
//! a program that nobody writes tests for. So each command is a function that *returns* something — the lines to
//! print, the files to write, what to exit with — and `main` reads the arguments, calls one, and does the I/O.
//!
//! The output being a value is also what makes a dry run and a real run share a code path: they produce the same
//! [`Command`] and only the caller's decision to write differs. A `--dry-run` implemented as a second branch through
//! the same logic is a branch that drifts.

use std::path::PathBuf;

use crate::args::{NewArgs, VerifyArgs};
use crate::template::Scaffold;
use crate::verify::{Target, VerifyReport, verify};

/// What a command decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Lines to print, and what to exit with.
    Reported {
        /// The text, one string per line.
        lines: Vec<String>,
        /// The exit code.
        code: u8,
        /// Whether the lines are a failure, so `main` writes them to the error stream.
        failure: bool,
    },
    /// A build to run.
    Build {
        /// What it will do.
        plan: Box<crate::build::BuildPlan>,
        /// The lines to print.
        lines: Vec<String>,
    },
    /// A signature to write beside a public key.
    Signature {
        /// Where the signature goes.
        path: PathBuf,
        /// The signature, as hex.
        signature: String,
        /// The public key, as hex, written beside it.
        public: String,
        /// The lines to print.
        lines: Vec<String>,
    },
    /// A package archive to write.
    Archive {
        /// Where the `.tgz` goes.
        target: PathBuf,
        /// The manifest, which becomes `package/manifest.json`.
        manifest: PathBuf,
        /// The artifacts the manifest names, by file name.
        artifacts: Vec<String>,
        /// The signature, when the package carries one.
        signature: Option<PathBuf>,
        /// A static index to write beside the archive, and its text.
        index: Option<(PathBuf, String)>,
        /// The lines to print.
        lines: Vec<String>,
    },
    /// A scaffold to write.
    ///
    /// The paths are **relative** to the root rather than joined, so the caller is the one that decides where the
    /// root is and an author's absolute path never appears in a message about a file inside their own plugin.
    Scaffold {
        /// Where the files go.
        root: PathBuf,
        /// The files, as `(path relative to the root, contents)`.
        files: Vec<(String, String)>,
        /// The lines to print, before anything is written.
        lines: Vec<String>,
    },
}

impl Outcome {
    /// The lines to print.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        match self {
            Self::Reported { lines, .. }
            | Self::Build { lines, .. }
            | Self::Signature { lines, .. }
            | Self::Archive { lines, .. }
            | Self::Scaffold { lines, .. } => lines,
        }
    }

    /// What the process should exit with.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Reported { code, .. } => *code,
            // A scaffold, a build and a signature that were decided are ones the caller will carry out; a failure to
            // decide them never reaches here.
            Self::Scaffold { .. } | Self::Build { .. } | Self::Signature { .. } | Self::Archive { .. } => 0,
        }
    }

    /// Whether the output is a failure.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        match self {
            Self::Reported { failure, .. } => *failure,
            Self::Scaffold { .. } | Self::Build { .. } | Self::Signature { .. } | Self::Archive { .. } => false,
        }
    }
}

/// What `new` will do.
///
/// # Errors
///
/// The scaffold's refusal, as a sentence: a reserved scope, an id the kernel would not accept, a version that is not
/// one. The message names the field, because it is read at the moment the author is least able to guess.
pub fn new_plugin(args: &NewArgs) -> Result<Outcome, String> {
    let scaffold = Scaffold::new(&args.plugin_id, &args.version, &args.title(), args.template)
        .map_err(|error| error.to_string())?;

    // Where it goes: the author's `--dir`, or a directory named after the wire slug — the name the artifact uses in
    // the registry, the cache and the log, so the author's directory matches all of them.
    let root = args
        .dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(&scaffold.directory));

    let mut lines: Vec<String> = scaffold
        .files
        .iter()
        .map(|file| {
            // The marker is in the left margin so an author scanning it sees which files the tool generated and which
            // are theirs to edit — the distinction that decides what a rebase will conflict with.
            let marker = if file.authored { "   " } else { "gen" };
            format!("{marker}  {}", file.path)
        })
        .collect();

    let files = if args.dry_run {
        Vec::new()
    }
    else {
        scaffold
            .files
            .iter()
            .map(|file| (file.path.clone(), file.contents.clone()))
            .collect()
    };

    if args.dry_run {
        lines.push("dry run: nothing was written".to_owned());
    }
    else {
        lines.push(format!(
            "\nwrote {}\nnext: edit manifest.json, then run `synra-plugin verify`",
            root.display()
        ));
    }

    Ok(Outcome::Scaffold { root, files, lines })
}

/// What `build` will do.
///
/// # Errors
///
/// The build's refusal, as a sentence: no manifest, one that does not parse, no runtime, or a UI plugin with no build
/// script. Each names the file, because it is read at the moment the author is least able to guess.
pub fn build_plugin(args: &crate::args::BuildArgs) -> Result<Outcome, String> {
    let plan = crate::build::BuildPlan::resolve(&args.dir).map_err(|error| error.to_string())?;

    let mut lines = plan.lines();
    lines.push(String::new());
    if args.dry_run {
        lines.push("dry run: nothing was run".to_owned());
    }
    else {
        // The commands are run by `main`, because running one is I/O and this function decides. What comes back is
        // what the *plan* says should have been produced, which `main` checks after the commands finish.
        lines.push(format!("{} command(s) to run", plan.steps.len()));
    }

    Ok(Outcome::Build { plan: Box::new(plan), lines })
}

mod sign;

pub use sign::sign_plugin;

/// What `verify` concluded.
#[must_use]
pub fn verify_plugin(args: &VerifyArgs) -> Outcome {
    let report: VerifyReport = verify(&Target::read(&args.dir));

    if args.json {
        let body = match serde_json::to_string_pretty(&report) {
            Ok(body) => body,
            Err(error) => {
                return Outcome::Reported {
                    lines: vec![format!("the report could not be written: {error}")],
                    code: 1,
                    failure: true,
                };
            }
        };
        return Outcome::Reported {
            lines: body.lines().map(str::to_owned).collect(),
            // The exit code follows the report, not its shape: a failing `verify` asked for JSON still failed, and a
            // build script reads the exit code rather than parsing the body.
            code: report.exit_code(),
            failure: !report.is_ok(),
        };
    }

    let mut lines = report.lines();
    if args.brief {
        // The suggestions are the lines that start with the indent the renderer uses. Dropping them is what a build
        // script's log wants: the finding without the advice.
        lines.retain(|line| !line.starts_with("      "));
    }

    Outcome::Reported { lines, code: report.exit_code(), failure: !report.is_ok() }
}

#[cfg(test)]
mod tests;
