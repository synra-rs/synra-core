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

/// Signs a plugin, or checks a signature.
///
/// # Errors
///
/// The signing error, as a sentence: a key that cannot be read, a manifest that does not parse, an artifact that is
/// not there.
pub fn sign_plugin(args: &crate::args::SignArgs) -> Result<Outcome, String> {
    // Generating a key is its own command because there is nothing to sign yet: an author does this once, before the
    // first publish, and printing the secret is the point — a tool that hid it would be one whose keys they cannot back
    // up, and a publisher who loses theirs cannot ship an update to a plugin users already trust.
    if args.generate_key {
        let key = crate::sign::SigningKeyFile::generate()?;
        return Ok(Outcome::Reported {
            lines: vec![
                "a new signing key. Keep the secret somewhere you can restore it from, and publish the public half."
                    .to_owned(),
                String::new(),
                format!("secret  {}", key.to_hex()),
                format!("public  {}", key.public_hex()),
            ],
            code: 0,
            failure: false,
        });
    }

    let content = crate::sign::SignedContent::read(&args.dir).map_err(|error| error.to_string())?;

    if let Some(signature_path) = &args.verify {
        let document = std::fs::read_to_string(signature_path).map_err(|error| {
            format!("the signature at {} could not be read: {error}", signature_path.display())
        })?;

        // ★ The trust store is **empty** here, and that is the honest answer for this command: an author checking
        // their own package has not made a decision about their own publisher, and a tool that trusted whatever it was
        // given would be a tool that verified nothing about who signed. What this proves is that the signature matches
        // the bytes — which is what the author is asking.
        let store = synra_plugin_api::publisher::PublisherTrustStore::new();
        let outcome = crate::sign::verify(&document, &args.dir, &store);

        // The key the author keeps beside the package, when there is one, is what makes this a check rather than a
        // formality: a signature by a key that is not the one they wrote down is a signature by somebody else.
        let pinned = crate::sign::expected_fingerprint(&args.dir);
        let pinned_matches = match (&outcome, &pinned) {
            (Ok(verified), Some(expected)) => verified.fingerprint == *expected,
            _ => true,
        };

        let ok = outcome.is_ok() && pinned_matches;
        let line = match (&outcome, ok) {
            (Ok(verified), true) => format!(
                "{} {} is signed by {} ({})",
                verified.plugin_id, verified.version, verified.publisher_id, verified.fingerprint
            ),
            (Ok(verified), false) => format!(
                "{} {} is signed, but not by the key in public-key.txt ({})",
                verified.plugin_id, verified.version, verified.fingerprint
            ),
            (Err(error), _) => format!(
                "the signature does not verify against {} {}: {error}",
                content.plugin_id, content.version
            ),
        };

        return Ok(Outcome::Reported {
            lines: vec![line],
            code: if ok { 0 } else { 1 },
            failure: !ok,
        });
    }

    let Some(key_path) = &args.key else {
        return Err("a signature needs `--key <path>`, or `--generate-key` to make one first".to_owned());
    };
    let key = crate::sign::SigningKeyFile::read(key_path).map_err(|error| error.to_string())?;
    let signature = key.sign(&content, &signed_at_now());

    Ok(Outcome::Signature {
        path: args.dir.join(synra_plugin_api::publisher::SIGNATURE_FILE),
        signature,
        public: key.public_hex(),
        lines: vec![
            format!("signed {} {}", content.plugin_id, content.version),
            format!("publisher {}", content.publisher_id),
            format!("fingerprint {}", key.fingerprint()),
        ],
    })
}

/// The moment a signature was made, as the document records it.
///
/// # Why this is not trusted by anything
///
/// It is a claim by whoever signed: a verifier that used it to decide which of two packages is newer would be letting
/// the package choose its own ordering. It is here so a person reading a `signature.json` in a repository can see when
/// it was made.
fn signed_at_now() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    format!("unix-ms:{millis}")
}

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
mod tests {
    use super::*;
    use crate::template::TemplateKind;

    /// A temporary directory that removes itself.
    struct Cleanup(PathBuf);

    impl Cleanup {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("synra-plugin-cli-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creates");
            Self(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn new_args(dir: Option<PathBuf>, dry_run: bool) -> NewArgs {
        NewArgs {
            plugin_id: "@synra-plugin/example".to_owned(),
            version: "0.1.0".to_owned(),
            title: None,
            template: TemplateKind::Headless,
            dir,
            dry_run,
        }
    }

    // ── new ───────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_scaffold_decides_a_root_and_a_file_list() {
        let outcome = new_plugin(&new_args(None, false)).expect("builds");
        let Outcome::Scaffold { files, .. } = &outcome else {
            panic!("expected a scaffold, got {outcome:?}");
        };
        assert!(files.iter().any(|(path, _)| path == "manifest.json"), "{files:?}");
        assert!(files.iter().all(|(path, _)| !path.starts_with('/')), "{files:?}");
    }

    #[test]
    fn the_root_defaults_to_the_wire_slug() {
        // The name the artifact uses in the registry, the cache and the log, so the author's directory matches all of
        // them — and a directory named after the raw id would contain a `/` and a scope.
        let outcome = new_plugin(&new_args(None, false)).expect("builds");
        let Outcome::Scaffold { root, files, .. } = &outcome else {
            panic!("expected a scaffold");
        };
        assert_eq!(root, &PathBuf::from("example"), "the root is not the wire slug");
        // And every path inside it is relative, so no message about a file mentions the author's home directory.
        for (path, _) in files {
            assert!(!path.contains('@'), "{path} is not a plain path");
            assert!(!std::path::Path::new(path).is_absolute(), "{path} is absolute");
        }
    }

    #[test]
    fn an_explicit_directory_is_used() {
        // So an author can scaffold into a monorepo without a move afterwards.
        let dir = Cleanup::new("explicit");
        let outcome = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
        let Outcome::Scaffold { root, .. } = &outcome else {
            panic!("expected a scaffold");
        };
        assert_eq!(root, dir.path());
    }

    #[test]
    fn a_dry_run_decides_no_files_but_the_same_listing() {
        // ★ The reason the outcome is a value: a dry run and a real run produce the same listing, so a `--dry-run`
        // implemented as a second branch would be a branch that drifts.
        let dry = new_plugin(&new_args(None, true)).expect("builds");
        let real = new_plugin(&new_args(None, false)).expect("builds");

        let Outcome::Scaffold { files: dry_files, lines: dry_lines, .. } = &dry else {
            panic!("expected a scaffold");
        };
        let Outcome::Scaffold { files: real_files, lines: real_lines, .. } = &real else {
            panic!("expected a scaffold");
        };

        assert!(dry_files.is_empty(), "a dry run decided to write {} files", dry_files.len());
        assert!(!real_files.is_empty());
        // The listing is the same, minus the closing sentence.
        assert_eq!(dry_lines[..dry_lines.len() - 1], real_lines[..real_lines.len() - 1]);
        assert!(dry_lines.last().expect("a line").contains("dry run"));
    }

    #[test]
    fn the_listing_marks_generated_files_apart_from_authored_ones() {
        // The distinction that decides what a rebase will conflict with.
        let outcome = new_plugin(&new_args(None, false)).expect("builds");
        let lines = outcome.lines();
        assert!(lines.iter().any(|line| line.starts_with("gen")), "{lines:?}");
        assert!(lines.iter().any(|line| line.starts_with("   ")), "{lines:?}");
    }

    #[test]
    fn a_reserved_scope_is_refused_with_a_sentence() {
        // The message is read at the moment the author is least able to guess.
        let mut args = new_args(None, false);
        args.plugin_id = "@synra/chat".to_owned();
        let error = new_plugin(&args).expect_err("refused");
        assert!(error.contains("plugin id"), "{error}");
    }

    #[test]
    fn an_unusable_version_is_refused() {
        let mut args = new_args(None, false);
        args.version = "latest".to_owned();
        assert!(new_plugin(&args).is_err());
    }

    #[test]
    fn a_built_scaffold_succeeds() {
        let outcome = new_plugin(&new_args(None, false)).expect("builds");
        assert_eq!(outcome.exit_code(), 0);
        assert!(!outcome.is_failure());
    }

    // ── verify ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn verifying_an_empty_directory_reports_a_failure() {
        // The answer an author needs when they ran the command from the wrong directory.
        let dir = Cleanup::new("empty");
        let outcome = verify_plugin(&VerifyArgs {
            dir: dir.path().to_path_buf(),
            json: false,
            brief: false,
        });
        assert_eq!(outcome.exit_code(), 1);
        assert!(outcome.is_failure());
        assert!(outcome.lines()[0].contains("manifest"), "{:?}", outcome.lines());
    }

    #[test]
    fn a_scaffold_verifies_cleanly() {
        // ★ The property that ties the two commands together: what `new` writes is what `verify` accepts. A scaffold
        // that does not verify is the failure an author meets first and cannot diagnose, because they do not yet know
        // what a correct manifest looks like.
        let dir = Cleanup::new("scaffolded");
        let outcome = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
        let Outcome::Scaffold { files, .. } = outcome else {
            panic!("expected a scaffold");
        };
        for (path, contents) in files {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("creates");
            }
            std::fs::write(&full, contents).expect("writes");
        }
        // The Wasm artifact `verify` looks for, because a build has not run.
        std::fs::write(dir.path().join("plugin.wasm"), vec![0u8; 64]).expect("writes");

        let report = verify_plugin(&VerifyArgs {
            dir: dir.path().to_path_buf(),
            json: false,
            brief: false,
        });
        assert_eq!(
            report.exit_code(),
            0,
            "a scaffolded plugin does not verify:\n{}",
            report.lines().join("\n")
        );
    }

    #[test]
    fn json_output_still_carries_the_exit_code() {
        // ★ A failing `verify` asked for JSON still failed. The exit code follows the report and not its shape, which
        // is what a build script reads rather than parsing the body.
        let dir = Cleanup::new("json-failure");
        let outcome = verify_plugin(&VerifyArgs {
            dir: dir.path().to_path_buf(),
            json: true,
            brief: false,
        });
        assert_eq!(outcome.exit_code(), 1);
        assert!(outcome.is_failure());
        let body = outcome.lines().join("\n");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(value["findings"].as_array().is_some_and(|f| !f.is_empty()));
    }

    #[test]
    fn json_output_for_a_healthy_plugin_succeeds() {
        let dir = Cleanup::new("json-ok");
        let _ = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
        // Write the scaffold by hand, since `new_plugin` only decides.
        let outcome = new_plugin(&new_args(Some(dir.path().to_path_buf()), false)).expect("builds");
        let Outcome::Scaffold { files, .. } = outcome else {
            panic!("expected a scaffold");
        };
        for (path, contents) in files {
            let full = dir.path().join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("creates");
            }
            std::fs::write(&full, contents).expect("writes");
        }
        std::fs::write(dir.path().join("plugin.wasm"), vec![0u8; 64]).expect("writes");

        let report = verify_plugin(&VerifyArgs {
            dir: dir.path().to_path_buf(),
            json: true,
            brief: false,
        });
        assert_eq!(report.exit_code(), 0, "{}", report.lines().join("\n"));
        assert!(!report.is_failure());
    }

    #[test]
    fn a_brief_report_drops_the_suggestions() {
        // What a build script's log wants: the finding without the advice.
        let dir = Cleanup::new("brief");
        let full = verify_plugin(&VerifyArgs {
            dir: dir.path().to_path_buf(),
            json: false,
            brief: false,
        });
        let brief = verify_plugin(&VerifyArgs {
            dir: dir.path().to_path_buf(),
            json: false,
            brief: true,
        });

        assert!(
            full.lines().iter().any(|line| line.starts_with("      ")),
            "the full report has no suggestions to drop: {:?}",
            full.lines()
        );
        assert!(
            !brief.lines().iter().any(|line| line.starts_with("      ")),
            "{:?}",
            brief.lines()
        );
        // And the verdict is unchanged, because the advice is not what decides.
        assert_eq!(full.exit_code(), brief.exit_code());
    }
}
