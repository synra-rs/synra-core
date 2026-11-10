use clap::{CommandFactory as _, Parser as _};

use crate::plan::{DEFAULT_DISCOVERY_PORT, DEFAULT_LISTEN_PORT, PlanError};
use super::{DaemonArgs, ENV_DATA_DIR, Parsed};

fn parse(args: &[&str]) -> Result<DaemonArgs, clap::Error> {
    DaemonArgs::try_parse_from(args)
}

fn parsed(args: &[&str]) -> DaemonArgs {
    parse(args).expect("parses")
}

#[test]
fn the_parser_is_internally_consistent() {
    // `clap`'s own check: two flags with one long name, a conflict that names a flag that does not exist, and so
    // on. A build failure rather than something a user finds.
    DaemonArgs::command().debug_assert();
}

#[test]
fn the_defaults_claim_the_directory_and_linger() {
    // Two daemons over one database is a correctness problem, and a daemon whose purpose is to keep serving after
    // the interface closes must not exit with it.
    let args = parsed(&["synra-daemon"]);
    let options = args.options();
    assert!(options.exclusive);
    assert!(options.linger);
    assert_eq!(options.listen_port, DEFAULT_LISTEN_PORT);
    assert_eq!(options.discovery_port, DEFAULT_DISCOVERY_PORT);
}

#[test]
fn a_diagnostic_run_does_not_claim_the_directory() {
    // For looking at a live installation: a user who wants to see what a running daemon thinks should not have to
    // stop it.
    let args = parsed(&["synra-daemon", "--diagnostic"]);
    assert!(!args.options().exclusive);
}

#[test]
fn diagnostic_and_exclusive_together_are_refused() {
    // They are opposites, and `clap` refusing both means the choice is never silently one of them.
    assert!(parse(&["synra-daemon", "--diagnostic", "--exclusive"]).is_err());
}

#[test]
fn a_daemon_can_be_told_to_exit_with_its_last_client() {
    let args = parsed(&["synra-daemon", "--exit-with-last-client"]);
    assert!(!args.options().linger);
}

#[test]
fn the_ports_can_be_moved() {
    // A user with two profiles needs to move them, which is the thing that collides.
    let args = parsed(&["synra-daemon", "--listen-port", "5000", "--discovery-port", "5001"]);
    let options = args.options();
    assert_eq!(options.listen_port, 5_000);
    assert_eq!(options.discovery_port, 5_001);
}

#[test]
fn a_port_outside_the_range_is_refused_by_the_parser() {
    // A `u16` cannot hold it, so `clap` refuses before the plan sees a number the socket layer would truncate.
    assert!(parse(&["synra-daemon", "--listen-port", "70000"]).is_err());
    assert!(parse(&["synra-daemon", "--listen-port", "-1"]).is_err());
    assert!(parse(&["synra-daemon", "--listen-port", "many"]).is_err());
}

#[test]
fn the_data_directory_can_be_moved() {
    let args = parsed(&["synra-daemon", "--data-dir", "/custom"]);
    assert_eq!(args.options().data_dir, std::path::PathBuf::from("/custom"));
}

#[test]
fn a_dry_run_is_a_flag_rather_than_a_mode() {
    // Given a real directory, because the point of a dry run is to exercise the same checks a start would — and a
    // fixture that skipped them would be testing a path the daemon does not take.
    let dir = tempfile::Builder::new().prefix("dry-run-flag").tempdir().expect("a temporary directory");
    let root = dir.path().display().to_string();
    let args = parsed(&["synra-daemon", "--data-dir", root.as_str(), "--dry-run"]);
    assert!(args.dry_run);
    assert!(Parsed::resolve(&args).is_ok());
}

#[test]
fn a_dry_run_reports_a_plan_that_would_be_refused() {
    // The whole value of a dry run: a user finds out before starting that their two ports collide.
    let args = parsed(&["synra-daemon", "--listen-port", "5000", "--discovery-port", "5000", "--dry-run"]);
    assert!(matches!(Parsed::resolve(&args), Err(PlanError::PortsCollide { port: 5_000 })));
}

#[test]
fn the_environment_variable_is_the_one_the_cli_uses() {
    // One spelling for both binaries, or `synra doctor` checks a directory the daemon does not use.
    assert_eq!(ENV_DATA_DIR, "SYNRA_DATA_DIR");
}
