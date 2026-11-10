use super::super::{Command, DbAction};
use super::{parse, parsed};

#[test]
fn logs_defaults_to_a_hundred_lines_and_no_follow() {
    let Command::Logs(args) = parsed(&["synra", "logs"]).command else {
        panic!("expected logs");
    };
    assert_eq!(args.lines, 100);
    assert!(!args.follow);
    assert!(!args.verbose);
    assert_eq!(args.trace, None);
}

#[test]
fn logs_follows_and_filters() {
    let Command::Logs(args) = parsed(&[
        "synra",
        "logs",
        "--follow",
        "--trace",
        "t1",
        "--lines",
        "10",
        "--verbose",
    ])
    .command
    else {
        panic!("expected logs");
    };
    assert!(args.follow);
    assert!(args.verbose);
    assert_eq!(args.trace.as_deref(), Some("t1"));
    assert_eq!(args.lines, 10);
}

#[test]
fn logs_follow_has_a_short_form() {
    // Because it is the flag a user types most, and typing `--follow` while watching a log is friction.
    let Command::Logs(args) = parsed(&["synra", "logs", "-f"]).command else {
        panic!("expected logs");
    };
    assert!(args.follow);
}

#[test]
fn a_line_count_that_is_not_a_number_is_refused() {
    assert!(parse(&["synra", "logs", "--lines", "many"]).is_err());
    assert!(parse(&["synra", "logs", "--lines", "-1"]).is_err());
}

// ── Doctor and db ─────────────────────────────────────────────────────────────────────────────

#[test]
fn doctor_reports_everything_by_default() {
    // A user running `doctor` wants the whole picture; `--failures-only` is for a script.
    let Command::Doctor(args) = parsed(&["synra", "doctor"]).command else {
        panic!("expected doctor");
    };
    assert!(!args.failures_only);
    assert_eq!(args.bundle, None);
}

#[test]
fn doctor_can_write_a_bundle_and_be_quiet() {
    let Command::Doctor(args) = parsed(&[
        "synra",
        "doctor",
        "--failures-only",
        "--bundle",
        "/tmp/d.json",
    ])
    .command
    else {
        panic!("expected doctor");
    };
    assert!(args.failures_only);
    assert_eq!(args.bundle.as_deref(), Some("/tmp/d.json"));
}

#[test]
fn db_dump_takes_an_optional_table() {
    let Command::Db(args) = parsed(&["synra", "db", "dump"]).command else {
        panic!("expected db");
    };
    let DbAction::Dump { table } = args.action else {
        panic!("expected dump");
    };
    assert_eq!(table, None);

    let Command::Db(args) = parsed(&["synra", "db", "dump", "--table", "plugins"]).command
    else {
        panic!("expected db");
    };
    let DbAction::Dump { table } = args.action else {
        panic!("expected dump");
    };
    assert_eq!(table.as_deref(), Some("plugins"));
}

#[test]
fn db_integrity_needs_nothing() {
    let Command::Db(args) = parsed(&["synra", "db", "integrity"]).command else {
        panic!("expected db");
    };
    assert!(matches!(args.action, DbAction::Integrity));
}

#[test]
fn db_restore_names_the_backup_to_restore_from() {
    let Command::Db(args) = parsed(&["synra", "db", "restore", "old.db"]).command else {
        panic!("expected db");
    };
    let DbAction::Restore { path } = args.action else {
        panic!("expected restore");
    };
    assert_eq!(path, std::path::PathBuf::from("old.db"));
}
