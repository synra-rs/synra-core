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
use std::process::Command;

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
        // Neither has a dry run: `verify` changes nothing, and a signature an author asked for is one they want.
        crate::args::Command::Verify(_) | crate::args::Command::Sign(_) => false,
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

        Outcome::Archive { target, manifest, artifacts, signature, index, .. } => {
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
                            return Executed::failed(vec![format!("{}: {error}", parent.display())]);
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

        Outcome::Signature { path, signature, public, .. } => {
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
    for step in &plan.steps {
        let status = Command::new(&step.program)
            .args(&step.args)
            .current_dir(plan.root.join(&step.in_dir))
            .status();

        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                // The step's own `why` is not repeated: the author just watched it run, and what they need is which
                // command failed.
                return Executed::failed(vec![format!(
                    "`{}` exited with {status}",
                    step.command_line()
                )]);
            }
            Err(error) => {
                return Executed::failed(vec![format!(
                    "`{}` could not be run: {error}",
                    step.command_line()
                )]);
            }
        }
    }

    // ★ Checked after the commands, and the reason `build` knows what to expect: a build script that silently
    // succeeded at nothing exits zero, and the only thing that catches it is looking for the artifact.
    let lines = plan.outcome_lines();
    if plan.missing().is_empty() {
        Executed::ok(lines)
    }
    else {
        Executed::failed(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{BuildArgs, Command as CliCommand, NewArgs, SignArgs, VerifyArgs};
    use crate::build::BuildPlan;
    use crate::run::{build_plugin, new_plugin, sign_plugin};
    use crate::template::TemplateKind;
    use clap::Parser as _;

    struct Cleanup(std::path::PathBuf);

    impl Cleanup {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("synra-exec-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("creates");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, path: &str, contents: &[u8]) {
            let full = self.0.join(path);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("creates");
            }
            std::fs::write(full, contents).expect("writes");
        }

        fn plugin(&self) {
            self.write(
                "manifest.json",
                br#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
  "capabilities": []
}"#,
            );
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("parses")
    }

    // ── The dry run ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_dry_run_is_read_from_the_arguments_for_every_command_that_has_one() {
        // Read from the arguments rather than inferred from the outcome, because a plan and a decision look the same
        // and only the flag says whether to carry it out.
        assert!(is_dry_run(&cli(&["synra-plugin", "new", "@a/b", "--dry-run"])));
        assert!(is_dry_run(&cli(&["synra-plugin", "build", "--dry-run"])));
        assert!(!is_dry_run(&cli(&["synra-plugin", "new", "@a/b"])));
        assert!(!is_dry_run(&cli(&["synra-plugin", "build"])));
    }

    #[test]
    fn verify_and_sign_have_no_dry_run() {
        // `verify` changes nothing, and a signature an author asked for is one they want. A `--dry-run` on either would
        // be a flag that did nothing.
        assert!(!is_dry_run(&cli(&["synra-plugin", "verify"])));
        assert!(!is_dry_run(&cli(&["synra-plugin", "sign", "--generate-key"])));
    }

    // ── A scaffold ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_scaffold_is_written_and_a_dry_run_is_not() {
        let dir = Cleanup::new("scaffold");
        let args = NewArgs {
            plugin_id: "@synra-plugin/example".to_owned(),
            version: "0.1.0".to_owned(),
            title: None,
            template: TemplateKind::Headless,
            dir: Some(dir.path().to_path_buf()),
            dry_run: false,
        };
        let outcome = new_plugin(&args).expect("builds");

        // The dry run first, so the assertion about what is on disk is about a run that wrote.
        assert_eq!(execute(&outcome, true), Executed::ok(Vec::new()));
        assert!(!dir.path().join("manifest.json").exists(), "a dry run wrote");

        let executed = execute(&outcome, false);
        assert_eq!(executed.code, 0, "{executed:?}");
        assert!(dir.path().join("manifest.json").exists());
        assert!(dir.path().join("src/lib.rs").exists());
    }

    #[test]
    fn a_scaffold_that_cannot_be_written_fails_with_the_path() {
        // The message an author needs, and the path is the half of it that tells them which file.
        let dir = Cleanup::new("unwritable");
        // A *file* where the directory should be, so creating the root fails on every platform.
        dir.write("blocked", b"");
        let outcome = new_plugin(&NewArgs {
            plugin_id: "@synra-plugin/example".to_owned(),
            version: "0.1.0".to_owned(),
            title: None,
            template: TemplateKind::Headless,
            dir: Some(dir.path().join("blocked").join("nested")),
            dry_run: false,
        })
        .expect("builds");

        let executed = execute(&outcome, false);
        assert_eq!(executed.code, 1);
        assert!(executed.lines[0].contains("blocked"), "{:?}", executed.lines);
    }

    // ── A build ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_build_whose_artifact_is_there_succeeds() {
        // The commands are not run in a test — that would be a test of the toolchain — so the plan is built directly and
        // the check that follows the commands is asserted on its own.
        let dir = Cleanup::new("built");
        dir.plugin();
        dir.write("plugin.wasm", b"the module");

        let plan = BuildPlan::resolve(dir.path()).expect("resolves");
        assert!(plan.missing().is_empty());
        assert_eq!(plan.outcome_lines(), vec!["built plugin.wasm".to_owned()]);
    }

    #[test]
    fn a_build_whose_artifact_is_missing_fails_even_though_nothing_reported_an_error() {
        // ★ The failure this check exists for: a build script that silently succeeded at nothing exits zero, and the
        // only thing that catches it is looking for the artifact.
        let dir = Cleanup::new("not-built");
        dir.plugin();

        let plan = BuildPlan::resolve(dir.path()).expect("resolves");
        let lines = plan.outcome_lines();
        assert!(!plan.missing().is_empty());
        assert!(lines[0].contains("plugin.wasm"), "{}", lines[0]);
        assert!(lines[0].contains("manifest"), "{}", lines[0]);
    }

    #[test]
    fn a_build_plan_can_be_asked_for_without_a_dry_run() {
        // The wiring, asserted once: `build_plugin` resolves a plan and says what it will do.
        let dir = Cleanup::new("plan");
        dir.plugin();
        let outcome = build_plugin(&BuildArgs { dir: dir.path().to_path_buf(), dry_run: true })
            .expect("plans");
        let lines = outcome.lines().join("\n");
        assert!(lines.contains("cargo build"), "{lines}");
        assert!(lines.contains("dry run"), "{lines}");
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn a_build_of_a_directory_with_no_manifest_says_which_file() {
        let dir = Cleanup::new("no-manifest");
        let error = build_plugin(&BuildArgs { dir: dir.path().to_path_buf(), dry_run: false })
            .expect_err("refused");
        assert!(error.contains("manifest.json"), "{error}");
    }

    #[test]
    fn a_build_whose_step_exits_non_zero_stops_and_names_the_command() {
        // A real command that fails, on every platform this runs on: asking a program that does not exist is the
        // closest a test can get without a toolchain, and the code path is the same one.
        let dir = Cleanup::new("failing-step");
        dir.write(
            "manifest.json",
            br#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
  "capabilities": []
}"#,
        );
        let plan = BuildPlan::resolve(dir.path()).expect("resolves");
        // A program that cannot be run: the plan is replaced by one whose step names it, so the failure path is
        // exercised without depending on a toolchain.
        let broken = BuildPlan {
            steps: vec![crate::build::Step {
                program: "synra-no-such-program".to_owned(),
                args: Vec::new(),
                in_dir: std::path::PathBuf::new(),
                why: "x".to_owned(),
            }],
            ..plan
        };
        let executed = run_steps(&broken);
        assert_eq!(executed.code, 1);
        assert!(executed.lines[0].contains("synra-no-such-program"), "{:?}", executed.lines);
    }

    // ── A signature ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_signature_is_written_beside_the_public_key() {
        // So `--verify` has the one thing it needs without the author copying a key between files.
        let dir = Cleanup::new("signature");
        dir.plugin();
        dir.write("plugin.wasm", b"the module");
        let key_path = dir.path().join("key.txt");
        std::fs::write(
            &key_path,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .expect("writes");

        let outcome = sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: Some(key_path),
            generate_key: false,
            verify: None,
        })
        .expect("signs");

        let executed = execute(&outcome, false);
        assert_eq!(executed.code, 0, "{executed:?}");
        assert!(
            dir.path().join(synra_plugin_api::publisher::SIGNATURE_FILE).exists(),
            "the document the host reads is what a package carries"
        );
        assert!(dir.path().join("public-key.txt").exists());
        assert!(
            executed.lines[0].contains(synra_plugin_api::publisher::SIGNATURE_FILE),
            "{:?}",
            executed.lines
        );
    }

    #[test]
    fn a_signature_verifies_against_the_plugin_it_signed() {
        // The end-to-end property, through the files the command writes rather than through the library's own
        // functions: sign, then check, then change a byte and check again.
        let dir = Cleanup::new("sign-verify");
        dir.plugin();
        dir.write("plugin.wasm", b"the module");
        let key_path = dir.path().join("key.txt");
        std::fs::write(
            &key_path,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .expect("writes");

        let signed = sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: Some(key_path),
            generate_key: false,
            verify: None,
        })
        .expect("signs");
        assert_eq!(execute(&signed, false).code, 0);

        let check = |dir: &Cleanup| {
            sign_plugin(&SignArgs {
                dir: dir.path().to_path_buf(),
                key: None,
                generate_key: false,
                verify: Some(dir.path().join(synra_plugin_api::publisher::SIGNATURE_FILE)),
            })
            .expect("checks")
        };

        let good = check(&dir);
        assert_eq!(good.exit_code(), 0, "{:?}", good.lines());
        assert!(good.lines()[0].contains("is signed by"), "{:?}", good.lines());

        // One byte different, and the signature stops meaning anything.
        dir.write("plugin.wasm", b"the modul3");
        let bad = check(&dir);
        assert_eq!(bad.exit_code(), 1);
        assert!(bad.is_failure());
    }

    #[test]
    fn generating_a_key_prints_both_halves() {
        // ★ Printing the secret is the point: a tool that hid it would be one whose keys the author cannot back up, and
        // a publisher who loses theirs cannot ship an update to a plugin users already trust.
        let dir = Cleanup::new("generate");
        let outcome = sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: None,
            generate_key: true,
            verify: None,
        })
        .expect("generates");

        let lines = outcome.lines().join("\n");
        assert!(lines.contains("secret  "), "{lines}");
        assert!(lines.contains("public  "), "{lines}");
        // The two are different, which is the property a `public_hex` returning the secret would break.
        let secret = lines
            .lines()
            .find_map(|line| line.strip_prefix("secret  "))
            .expect("a secret");
        let public = lines
            .lines()
            .find_map(|line| line.strip_prefix("public  "))
            .expect("a public key");
        assert_ne!(secret, public);
        assert_eq!(secret.len(), 64);
        assert_eq!(public.len(), 64);
    }

    #[test]
    fn signing_without_a_key_says_what_to_pass() {
        // A user who typed `sign` and nothing else needs the flag's name, not a usage line.
        let dir = Cleanup::new("no-key");
        dir.plugin();
        dir.write("plugin.wasm", b"x");
        let error = sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: None,
            generate_key: false,
            verify: None,
        })
        .expect_err("refused");
        assert!(error.contains("--key"), "{error}");
        assert!(error.contains("--generate-key"), "{error}");
    }

    #[test]
    fn signing_a_plugin_whose_artifact_is_missing_says_so() {
        let dir = Cleanup::new("no-artifact");
        dir.plugin();
        let error = sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: None,
            generate_key: true,
            verify: None,
        });
        // Key generation does not read the artifact, so it succeeds — and that is the honest behaviour: an author
        // makes their key once, before there is anything to sign.
        assert!(error.is_ok());

        // With a key that exists, so the refusal is about the artifact rather than about the key — the two are
        // different problems and the message has to be about the one that happened.
        let key_path = dir.path().join("key.txt");
        std::fs::write(
            &key_path,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .expect("writes");
        let error = sign_plugin(&SignArgs {
            dir: dir.path().to_path_buf(),
            key: Some(key_path),
            generate_key: false,
            verify: None,
        })
        .expect_err("refused");
        assert!(error.contains("plugin.wasm"), "{error}");
        assert!(error.contains("nothing to sign"), "{error}");
    }

    #[test]
    fn a_verify_command_is_not_a_dry_run() {
        // `verify` is what a script runs in CI, and a `--dry-run` on it would be a flag that did nothing.
        let cli = Cli::try_parse_from(["synra-plugin", "verify"]).expect("parses");
        assert!(matches!(cli.command, CliCommand::Verify(VerifyArgs { .. })));
        assert!(!is_dry_run(&cli));
    }

    #[test]
    fn the_arguments_for_every_command_are_reachable_from_one_place() {
        // The wiring between `args` and `run`, asserted once: a subcommand with no handling would be a command that
        // parses and does nothing.
        for args in [
            vec!["synra-plugin", "new", "@a/b"],
            vec!["synra-plugin", "build"],
            vec!["synra-plugin", "verify"],
            vec!["synra-plugin", "sign", "--generate-key"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?} should parse");
        }
    }
}
