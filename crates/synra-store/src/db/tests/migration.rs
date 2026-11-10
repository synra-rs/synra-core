use super::*;

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
