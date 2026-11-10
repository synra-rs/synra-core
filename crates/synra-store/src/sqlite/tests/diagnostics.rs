use crate::records::RowError;
use super::super::{DbError, SynraDb};
use super::migrated;

#[test]
fn a_boolean_column_the_schema_forbids_is_reported_rather_than_read_as_true() {
    // ★ The `CHECK (x IN (0, 1))` is enforced by the engine, so this row can only arrive from a corrupt file or a
    // table created outside the migrations — which is exactly the case a reader must not interpret. The assertion is
    // that the schema refuses it, so the reader never sees it.
    let db = migrated();
    let refused = db.connection.execute(
        "INSERT INTO paired_devices \
         (device_id, display_name, platform, features, paired_at_ms, last_seen_ms, blocked) \
         VALUES ('d', 'n', 'p', '[]', 0, 0, 2)",
        [],
    );
    assert!(refused.is_err(), "the schema allowed blocked = 2");
}

#[test]
fn the_counts_report_every_table_including_an_absent_one() {
    // A table the migration has not created is reported as absent rather than as an error, because `synra db dump`
    // on a fresh file is a legitimate thing to run.
    let empty = SynraDb::open_in_memory().expect("opens");
    let counts = empty.counts().expect("counts");
    assert_eq!(counts.len(), crate::db::TABLES.len());
    assert!(counts.iter().all(|(_, count)| count.is_none()), "a fresh file has no tables");

    let db = migrated();
    let counts = db.counts().expect("counts");
    assert!(counts.iter().all(|(_, count)| count.is_some()), "{counts:?}");
    for (table, count) in &counts {
        assert_eq!(
            *count,
            Some(i64::from(table == "plugin_authority_clock")),
            "{table}"
        );
    }
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        DbError::Open { path: std::path::PathBuf::from("/tmp/x"), why: "denied".to_owned() },
        DbError::Statement { why: "no such table".to_owned() },
        DbError::FromTheFuture { found: 9, known: 3 },
        DbError::Row(RowError::Missing { column: "device_id" }),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And the future-schema message names both versions, because "incompatible" alone leaves the user with nothing.
    let text = errors[2].to_string();
    assert!(text.contains('9') && text.contains('3'), "{text}");
}
