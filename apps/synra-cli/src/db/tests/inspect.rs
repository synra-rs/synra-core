use crate::args::{DbAction, OutputFormat};
use crate::session::CommandOutcome;
use super::super::outcome_at;
use super::{Root, args};

#[test]
fn integrity_answers_rather_than_refusing() {
    // ★ The test that would have failed before this module existed: every `db` invocation ended in "this command
    // reads the database directly, which is not implemented yet", so a user with a suspect database had nothing to run.
    let root = Root::new("integrity");
    let outcome = outcome_at(&root.0, Some(OutputFormat::Text), &args(DbAction::Integrity));

    match outcome {
        CommandOutcome::Lines(lines) => {
            assert!(lines.join(" ").contains("sound"), "{lines:?}");
        }
        other => panic!("a fresh database is sound, got {other:?}"),
    }
}

#[test]
fn a_dump_of_one_table_carries_that_table() {
    let root = Root::new("dump-config");
    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Json),
        &args(DbAction::Dump { table: Some("config".to_owned()) }),
    );

    match outcome {
        // An empty `config` is an empty list, not an error and not `null`: the table exists and holds nothing, which
        // is a fact about the database rather than about the command.
        CommandOutcome::Json { body, ok } => {
            assert!(ok, "{body}");
            assert_eq!(body, "[]", "{body}");
        }
        other => panic!("expected JSON, got {other:?}"),
    }
}

#[test]
fn a_dump_of_an_unknown_table_names_the_ones_it_knows() {
    // ★ Refused rather than answered with `{}`, which would read as "that table is empty" — a fact about the
    // user's data rather than about their spelling. The message lists the alternatives so the next try is a good one.
    let root = Root::new("dump-typo");
    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Dump { table: Some("devicez".to_owned()) }),
    );

    match outcome {
        CommandOutcome::Failed(message) => {
            assert!(message.contains("devicez"), "{message}");
            assert!(message.contains("devices"), "the known tables are listed: {message}");
        }
        other => panic!("a typo is a failure, got {other:?}"),
    }
}

#[test]
fn every_table_is_in_a_dump_of_all_of_them() {
    // The single-table path and `all` share one list, so this is what stops a table being reachable by name and
    // missing from the whole dump.
    let root = Root::new("dump-all");
    let outcome = outcome_at(&root.0, Some(OutputFormat::Json), &args(DbAction::Dump { table: None }));

    let CommandOutcome::Json { body, ok } = outcome else {
        panic!("expected JSON");
    };
    assert!(ok, "{body}");
    for table in ["identity", "devices", "seen", "plugins", "grants", "config"] {
        assert!(body.contains(&format!("\"{table}\"")), "{table} is missing from {body}");
    }
}
