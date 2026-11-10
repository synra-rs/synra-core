use clap::Parser as _;

use crate::args::DaemonArgs;
use super::super::{Startup, looks_like_a_data_dir, startup};
use super::{Cleanup, args};

#[test]
fn a_diagnostic_run_starts_even_when_the_directory_is_held() {
    // A user who wants to see what a running daemon thinks should not have to stop it.
    let dir = Cleanup::new("diagnostic");
    dir.write_claim(1_000, 4_242);
    let startup = startup(&args(&dir.data(), &["--diagnostic"]), 2_000);
    assert!(startup.may_run(), "{startup:?}");
    assert!(startup.lines().iter().any(|line| line.contains("diagnostic run")), "{:?}", startup.lines());
}

#[test]
fn a_dry_run_succeeds_without_claiming_anything() {
    // It did exactly what was asked of it, and exiting non-zero would make a script that checks a configuration
    // treat a good configuration as an error.
    let dir = Cleanup::new("dry");
    let startup = startup(&args(&dir.data(), &["--dry-run"]), 0);
    assert_eq!(startup.exit_code(), 0);
    assert!(!startup.may_run(), "a dry run does not start a kernel");
    assert!(startup.lines().iter().any(|line| line.contains("dry run")), "{:?}", startup.lines());
    // And nothing was written.
    assert!(!dir.lock_path().exists());
}

#[test]
fn a_dry_run_reports_a_configuration_that_would_be_refused() {
    // The whole value of a dry run: a user finds out before starting that their two ports collide.
    let dir = Cleanup::new("dry-refused");
    let root = dir.data().display().to_string();
    let args = DaemonArgs::try_parse_from([
        "synra-daemon",
        "--data-dir",
        root.as_str(),
        "--listen-port",
        "5000",
        "--discovery-port",
        "5000",
        "--dry-run",
    ])
    .expect("parses");

    let startup = startup(&args, 0);
    assert!(matches!(startup, Startup::Refused { .. }), "{startup:?}");
    assert_eq!(startup.exit_code(), 1);
    assert!(startup.failure().expect("a reason").contains("5000"));
}

#[test]
fn a_refused_startup_prints_nothing_of_the_plan() {
    // The plan describes an installation that will not exist, and printing it would suggest otherwise.
    let dir = Cleanup::new("refused-lines");
    let root = dir.data().display().to_string();
    let args = DaemonArgs::try_parse_from([
        "synra-daemon",
        "--data-dir",
        root.as_str(),
        "--listen-port",
        "5000",
        "--discovery-port",
        "5000",
    ])
    .expect("parses");
    assert!(startup(&args, 0).lines().is_empty());
}

// ── The report ────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_report_describes_a_start_that_will_happen() {
    let dir = Cleanup::new("report");
    let startup = startup(&args(&dir.data(), &[]), 0);
    let report = startup.report().expect("a report");
    assert!(!report.can_prompt_the_user, "this host has no window");
    assert!(report.exclusive);
    assert!(report.linger);
    assert_eq!(report.listen_port, 0);
}

#[test]
fn a_refused_startup_reports_nothing() {
    // A bundle that described a plan for a start that was refused would describe an installation that does not
    // exist.
    let dir = Cleanup::new("report-refused");
    dir.write_claim(1_000, 1);
    assert!(startup(&args(&dir.data(), &[]), 2_000).report().is_none());
}

#[test]
fn the_report_serialises_for_a_bundle() {
    let dir = Cleanup::new("report-json");
    let report = startup(&args(&dir.data(), &[]), 0).report().expect("a report");
    let json = serde_json::to_value(&report).expect("serialises");
    assert_eq!(json["canPromptTheUser"], false);
    assert_eq!(json["linger"], true);
    assert!(json["dataDir"].is_string());
}

// ── Recognising a data directory ──────────────────────────────────────────────────────────────

#[test]
fn a_directory_with_a_lock_or_a_database_looks_like_one() {
    // The question the CLI's `doctor` also asks, and one answer for both is how the two stay in step.
    let dir = Cleanup::new("recognise");
    assert!(!looks_like_a_data_dir(&dir.data()), "an empty directory is not one");

    std::fs::write(dir.data().join("synra.db"), "").expect("writes");
    assert!(looks_like_a_data_dir(&dir.data()));

    let other = Cleanup::new("recognise-lock");
    std::fs::write(other.data().join(crate::plan::LOCK_FILE_NAME), "").expect("writes");
    assert!(looks_like_a_data_dir(&other.data()));
}
