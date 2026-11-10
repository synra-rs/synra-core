use clap::Parser as _;
use crate::args::{Cli, VerifyArgs};
use crate::args::Command as CliCommand;
use super::super::is_dry_run;
use super::cli;

#[test]
fn a_dry_run_is_read_from_the_arguments_for_every_command_that_has_one() {
    // Read from the arguments rather than inferred from the outcome, because a plan and a decision look the same
    // and only the flag says whether to carry it out.
    assert!(is_dry_run(&cli(&[
        "synra-plugin",
        "new",
        "@a/b",
        "--dry-run"
    ])));
    assert!(is_dry_run(&cli(&["synra-plugin", "build", "--dry-run"])));
    assert!(!is_dry_run(&cli(&["synra-plugin", "new", "@a/b"])));
    assert!(!is_dry_run(&cli(&["synra-plugin", "build"])));
}

#[test]
fn verify_and_sign_have_no_dry_run() {
    // `verify` changes nothing, and a signature an author asked for is one they want. A `--dry-run` on either would
    // be a flag that did nothing.
    assert!(!is_dry_run(&cli(&["synra-plugin", "verify"])));
    assert!(!is_dry_run(&cli(&[
        "synra-plugin",
        "sign",
        "--generate-key"
    ])));
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
