use super::*;

#[test]
fn an_integrity_check_that_passes_is_sound() {
    assert_eq!(interpret_integrity(&["ok".to_owned()]), Health::Sound);
    assert!(Health::Sound.is_sound());
    assert!(!Health::Sound.needs_user_attention());
    assert!(Health::Sound.explain().contains("passed"));
}

#[test]
fn an_integrity_check_that_finds_a_problem_is_reported() {
    let health = interpret_integrity(&["row 5 missing from index".to_owned()]);
    match &health {
        Health::Corrupt { detail } => assert!(detail.contains("missing from index")),
        other => panic!("expected damage, got {other:?}"),
    }
    assert!(!health.is_sound());
    assert!(health.needs_user_attention());
    // The sentence has to tell the user what happens next, not only that something broke.
    assert!(health.explain().contains("backup"));
}

#[test]
fn an_integrity_check_that_cannot_run_is_not_a_failure() {
    // Not being able to tell is a different claim from the database being damaged, and telling a user their
    // data is corrupt when it is not is the worse mistake.
    let health = interpret_integrity(&[]);
    assert!(matches!(health, Health::Unknown { .. }));
    assert!(!health.is_sound());
    assert!(!health.needs_user_attention());
}

#[test]
fn the_version_table_statement_is_idempotent() {
    // It runs before the first migration, and on a resumed database it runs again.
    assert!(VERSION_TABLE.contains("IF NOT EXISTS"));
}

#[test]
fn a_migration_outcome_displays_its_summary() {
    let outcome = MigrationOutcome { applied: vec![1, 2], version: 2 };
    assert_eq!(outcome.to_string(), outcome.describe());
    assert!(outcome.describe().contains('2'));
}

#[test]
fn schema_errors_explain_themselves() {
    let errors = vec![
        SchemaError::TooNew { found: 9, known: 5 },
        SchemaError::MalformedList("x"),
        SchemaError::StatementFailed {
            version: 1,
            name: "init",
            index: 0,
            detail: "x".to_owned(),
        },
        SchemaError::Corrupt("x".to_owned()),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text:?}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}

#[test]
fn the_too_new_message_names_both_versions() {
    // The message is what a user sees, and "the database is too new" without the numbers gives them nothing
    // to act on.
    let text = SchemaError::TooNew { found: 9, known: 5 }.to_string();
    assert!(text.contains('9'), "{text}");
    assert!(text.contains('5'), "{text}");
}
