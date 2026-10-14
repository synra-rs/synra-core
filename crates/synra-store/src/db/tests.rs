//! The schema module's tests.

use super::*;
#[test]
fn the_migration_list_is_a_sequence_from_one() {
    // A gap would mean a version whose shape nobody defined, and an engine applying steps in order would
    // silently skip from one shape to a different one.
    assert_eq!(check_migration_list(MIGRATIONS), Ok(()));
    // That the list reaches *some* version, and that the version it reaches is the last entry's. A literal here would
    // have to be edited every time a migration is appended, which is the change this test is supposed to be silent about.
    assert_eq!(latest_version(), MIGRATIONS.last().map_or(0, |migration| migration.version));
    assert!(latest_version() > 0, "a schema with no migrations cannot open anything");
}

#[test]
fn a_malformed_list_is_refused() {
    // The check exists so a mistake in the list is caught in a test rather than on a user's device, so it has
    // to actually reject the shapes that would break.
    let gap = [
        Migration { version: 1, name: "a", statements: &["SELECT 1"] },
        Migration { version: 3, name: "c", statements: &["SELECT 1"] },
    ];
    assert!(matches!(check_migration_list(&gap), Err(SchemaError::MalformedList(_))));

    let nameless = [Migration { version: 1, name: "", statements: &["SELECT 1"] }];
    assert!(check_migration_list(&nameless).is_err());

    let empty = [Migration { version: 1, name: "a", statements: &[] }];
    assert!(check_migration_list(&empty).is_err());

    // An empty list is not malformed; it is a build with no schema, which is what version zero means.
    assert_eq!(check_migration_list(&[]), Ok(()));
    assert_eq!(latest_version_of(&[]), 0);
}

/// The version of an arbitrary list, so the empty case can be asserted without touching the constant.
fn latest_version_of(migrations: &[Migration]) -> u32 {
    migrations.last().map_or(0, |migration| migration.version)
}

#[test]
fn every_table_the_design_names_is_created_somewhere() {
    // A table named in the document and missing from the schema is a feature that fails at its first use,
    // and the failure appears nowhere near the schema.
    let all: String = MIGRATIONS
        .iter()
        .flat_map(|migration| migration.statements.iter())
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    for table in TABLES {
        assert!(
            all.contains(&format!("CREATE TABLE {table}"))
                || all.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "{table} is named in the design and never created"
        );
    }
}

#[test]
fn a_published_migration_is_never_edited() {
    // The rule, asserted as a fact about the list: each version appears once and the numbering is dense. An
    // edit to a published step is invisible here, which is why the design document states the rule as a
    // policy rather than something the code can check — but a *second* step with the same version is caught.
    let mut seen = std::collections::HashSet::new();
    for migration in MIGRATIONS {
        assert!(seen.insert(migration.version), "version {} appears twice", migration.version);
    }
}

#[test]
fn the_pragmas_have_the_values_the_schema_relies_on() {
    let value = |name: &str| {
        PRAGMAS
            .iter()
            .find(|(pragma, _)| *pragma == name)
            .map(|(_, value)| *value)
    };

    // Off by default in SQLite, and the schema's cascades depend on it: without this, deleting a plugin
    // leaves its grants behind forever.
    assert_eq!(value("foreign_keys"), Some("ON"));
    assert_eq!(value("journal_mode"), Some("WAL"));
    // A connection that does not wait for a brief lock surfaces as a spurious error in the interface.
    assert_eq!(value("busy_timeout"), Some("5000"));
    assert_eq!(value("temp_store"), Some("MEMORY"));
}

#[test]
fn schema_state_recognises_an_empty_database() {
    assert_eq!(schema_state(None), SchemaState::Empty);
    // Zero and absent mean the same thing: nothing has been applied.
    assert_eq!(schema_state(Some(0)), SchemaState::Empty);
    assert!(SchemaState::Empty.is_usable());
    assert_eq!(SchemaState::Empty.pending().len(), MIGRATIONS.len());
}

#[test]
fn schema_state_recognises_a_database_at_the_latest_version() {
    let state = schema_state(Some(latest_version()));
    assert_eq!(state, SchemaState::At { version: latest_version() });
    assert!(state.is_usable());
    assert!(state.pending().is_empty(), "nothing to do at the latest version");
}

#[test]
fn schema_state_lists_only_the_steps_that_are_pending() {
    let state = schema_state(Some(2));
    let pending: Vec<u32> = state.pending().iter().map(|migration| migration.version).collect();
    let after_two: Vec<u32> =
        MIGRATIONS.iter().map(|migration| migration.version).filter(|version| *version > 2).collect();
    assert_eq!(pending, after_two);
}

#[test]
fn a_newer_database_is_refused_rather_than_migrated() {
    // A device that ran a newer build and then an older one has a schema whose columns this build does not
    // know about. Running this build's migrations would leave the shape neither version expects.
    let state = schema_state(Some(latest_version() + 1));
    match state {
        SchemaState::Newer { found, known } => {
            assert_eq!(found, latest_version() + 1);
            assert_eq!(known, latest_version());
        }
        other => panic!("expected a newer database, got {other:?}"),
    }
    assert!(!state.is_usable());
    assert!(state.pending().is_empty());
}

#[test]
fn applying_to_an_empty_database_runs_every_step() {
    let mut executed: Vec<String> = Vec::new();
    let outcome = apply(None, &mut |statement| {
        executed.push(statement.to_owned());
        Ok(())
    })
    .expect("applies");

    // Derived from the list rather than written out. A migration is appended far more often than the list is
    // rearranged, and a literal here turns appending one — a routine change — into a failure that says nothing about
    // whether the new migration is right.
    let every_version: Vec<u32> = MIGRATIONS.iter().map(|migration| migration.version).collect();
    assert_eq!(outcome.applied, every_version);
    assert_eq!(outcome.version, latest_version());
    assert!(outcome.changed_anything());
    assert!(
        outcome.describe().contains(&format!("{} migration", MIGRATIONS.len())),
        "the report names how many steps ran: {}",
        outcome.describe()
    );

    let total: usize = MIGRATIONS.iter().map(|migration| migration.statements.len()).sum();
    assert_eq!(executed.len(), total, "every statement ran exactly once");
}

#[test]
fn applying_to_a_current_database_runs_nothing() {
    let mut executed = 0usize;
    let outcome = apply(Some(latest_version()), &mut |_| {
        executed += 1;
        Ok(())
    })
    .expect("applies");

    assert_eq!(executed, 0);
    assert!(!outcome.changed_anything());
    assert!(outcome.describe().contains("already at version"));
}

#[test]
fn applying_resumes_from_the_recorded_version() {
    // A half-finished migration must not be repeated: the first step may have created tables, and running it
    // again would fail on the second device that resumed.
    let mut versions: Vec<String> = Vec::new();
    let outcome = apply(Some(2), &mut |statement| {
        versions.push(statement.to_owned());
        Ok(())
    })
    .expect("applies");

    // Everything after the recorded version, derived from the list so appending a migration does not edit this test.
    let from_three: Vec<u32> =
        MIGRATIONS.iter().map(|migration| migration.version).filter(|version| *version > 2).collect();
    assert_eq!(outcome.applied, from_three);
    // And none of the earlier steps' statements appear.
    let earlier: Vec<String> = MIGRATIONS[..2]
        .iter()
        .flat_map(|migration| migration.statements.iter())
        .map(|statement| (*statement).to_owned())
        .collect();
    for statement in earlier {
        assert!(!versions.contains(&statement), "an applied step ran again");
    }
}

#[test]
fn a_failed_statement_names_the_migration_and_the_statement() {
    // The log line is what somebody has to act on, so it has to say which step and which statement rather
    // than just that migration failed.
    let mut count = 0usize;
    let result = apply(None, &mut |_| {
        count += 1;
        if count == 3 { Err("table already exists".to_owned()) } else { Ok(()) }
    });

    match result {
        Err(SchemaError::StatementFailed { version, name, index, detail }) => {
            assert_eq!(version, 1, "the third statement is in the first migration");
            assert_eq!(name, "init");
            assert_eq!(index, 2);
            assert!(detail.contains("already exists"));
        }
        other => panic!("expected a statement failure, got {other:?}"),
    }
}

#[test]
fn a_failed_migration_reports_the_versions_that_succeeded() {
    // The recorded version is left at the last step that completed, so the next run resumes rather than
    // repeating work — which means the caller has to be told where it got to.
    let mut count = 0usize;
    let result = apply(Some(1), &mut |_| {
        count += 1;
        // The second migration's first statement fails.
        if count == 1 { Err("nope".to_owned()) } else { Ok(()) }
    });

    match result {
        Err(SchemaError::StatementFailed { version, .. }) => assert_eq!(version, 2),
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn applying_to_a_newer_database_is_refused_before_running_anything() {
    let mut executed = 0usize;
    let result = apply(Some(latest_version() + 5), &mut |_| {
        executed += 1;
        Ok(())
    });

    assert!(matches!(result, Err(SchemaError::TooNew { .. })));
    assert_eq!(executed, 0, "nothing may run against a schema this build cannot understand");
}

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
