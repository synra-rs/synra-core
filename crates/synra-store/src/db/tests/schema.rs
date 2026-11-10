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
