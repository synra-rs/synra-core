use synra_store::{Health, Paths, SynraDb};
use crate::args::{DbAction, OutputFormat};
use crate::session::CommandOutcome;
use super::super::outcome_at;
use super::{Root, args};

#[test]
fn a_backup_writes_a_file_the_engine_can_open() {
    let root = Root::new("backup");
    let destination = root.0.join("copy.db");
    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Backup { path: destination.clone() }),
    );

    assert!(matches!(outcome, CommandOutcome::Lines(_)), "{outcome:?}");
    assert!(destination.is_file(), "no file was written");

    // ★ Opened rather than merely sized. A copy of a live database is a file that may not open at all, which is
    // the whole reason `VACUUM INTO` is used instead — so "it exists" is not the assertion that matters.
    let mut copy = SynraDb::open(&destination).expect("the backup opens");
    copy.migrate().expect("and is a usable database");
    assert!(matches!(copy.health().expect("a check"), Health::Sound));
}

#[test]
fn a_backup_does_not_overwrite_one_that_is_already_there() {
    // ★ The caller is usually a user making a backup *before* something risky, and this tool cannot know whether
    // the file already there is the one they meant to keep. Refusing is the only answer that cannot destroy it.
    let root = Root::new("backup-exists");
    let destination = root.0.join("copy.db");
    std::fs::write(&destination, b"something the user put here").expect("a file");

    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Backup { path: destination.clone() }),
    );

    match outcome {
        CommandOutcome::Failed(message) => {
            assert!(message.contains("already exists"), "{message}");
            // And the file is untouched, which is the property rather than the message.
            assert_eq!(
                std::fs::read(&destination).expect("still there"),
                b"something the user put here"
            );
        }
        other => panic!("overwriting a backup must fail, got {other:?}"),
    }
}

#[test]
fn a_restore_puts_the_backup_back_and_keeps_what_was_there() {
    // ★ The recovery path the integrity command has been telling users about: "restore from a backup" had no command
    // until this. The file that was replaced stays beside it, because "looks damaged" is a diagnosis.
    let root = Root::new("restore");
    let destination = root.0.join("before.db");
    {
        let paths = Paths::under(&root.0);
        let mut db = SynraDb::open(&paths.db_path()).expect("opens");
        db.migrate().expect("migrates");
        db.set_config("test.key", &serde_json::json!("from the backup"), 1)
            .expect("written");
        db.backup_to(&destination).expect("a backup");
        db.set_config("test.key", &serde_json::json!("changed after"), 2)
            .expect("written");
    }

    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Restore { path: destination }),
    );
    match outcome {
        CommandOutcome::Lines(lines) => assert!(lines[0].contains("restored"), "{lines:?}"),
        other => panic!("the restore reported a failure: {other:?}"),
    }

    let paths = Paths::under(&root.0);
    let db = SynraDb::open(&paths.db_path()).expect("the restored database opens");
    let config = db.config().expect("reads");
    assert_eq!(
        config.iter().find(|row| row.key == "test.key").map(|row| row.value.clone()),
        Some(serde_json::json!("from the backup").to_string()),
        "the backup's value was not restored"
    );
    let previous = std::fs::read_dir(&root.0)
        .expect("reads")
        .flatten()
        .find(|entry| entry.file_name().to_string_lossy().contains(".before-restore-"));
    assert!(previous.is_some(), "the database that was replaced was not kept");
}

#[test]
fn a_damaged_backup_is_refused_and_the_database_is_untouched() {
    let root = Root::new("restore-damaged");
    let damaged = root.0.join("damaged.db");
    {
        let paths = Paths::under(&root.0);
        let mut db = SynraDb::open(&paths.db_path()).expect("opens");
        db.migrate().expect("migrates");
        db.set_config("test.key", &serde_json::json!("current"), 1).expect("written");
    }
    std::fs::write(&damaged, b"not a database").expect("the damaged file");

    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Restore { path: damaged }),
    );
    assert!(matches!(outcome, CommandOutcome::Failed(_)), "{outcome:?}");

    let paths = Paths::under(&root.0);
    let db = SynraDb::open(&paths.db_path()).expect("the current database still opens");
    let config = db.config().expect("reads");
    assert_eq!(
        config.iter().find(|row| row.key == "test.key").map(|row| row.value.clone()),
        Some(serde_json::json!("current").to_string()),
        "a refused restore changed the database"
    );
}

#[test]
fn a_container_export_and_import_round_trip() {
    // ★ The wrapper around the restore path: the same database replacement, with the plugin list a user has to
    // reinstall carried beside it. The plugin appears in the answer because the artifacts are deliberately absent.
    let root = Root::new("container");
    let archive = root.0.join("device.synrabackup");
    {
        let paths = Paths::under(&root.0);
        let mut db = SynraDb::open(&paths.db_path()).expect("opens");
        db.migrate().expect("migrates");
        db.set_config("test.key", &serde_json::json!("from the container"), 1)
            .expect("written");
        db.insert_plugin("@acme/hello", true, true, "healthy", 1, 1).expect("inserted");
    }

    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Export { path: archive.clone() }),
    );
    match outcome {
        CommandOutcome::Lines(lines) => {
            assert!(lines[0].contains("plugin(s)"), "{lines:?}");
        }
        other => panic!("the export reported a failure: {other:?}"),
    }

    {
        let paths = Paths::under(&root.0);
        let db = SynraDb::open(&paths.db_path()).expect("opens");
        db.set_config("test.key", &serde_json::json!("changed after"), 2)
            .expect("written");
    }

    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Import { path: archive }),
    );
    match outcome {
        CommandOutcome::Lines(lines) => {
            assert!(lines[0].contains("imported"), "{lines:?}");
            assert!(
                lines.iter().any(|line| line.contains("@acme/hello")),
                "the reinstall list is missing: {lines:?}"
            );
        }
        other => panic!("the import reported a failure: {other:?}"),
    }

    let paths = Paths::under(&root.0);
    let db = SynraDb::open(&paths.db_path()).expect("the imported database opens");
    let config = db.config().expect("reads");
    assert_eq!(
        config.iter().find(|row| row.key == "test.key").map(|row| row.value.clone()),
        Some(serde_json::json!("from the container").to_string()),
        "the container's value was not imported"
    );
    assert_eq!(db.plugins().expect("reads").len(), 1, "the plugin record came back");
}

#[test]
fn an_import_of_something_that_is_not_a_container_is_refused() {
    let root = Root::new("import-foreign");
    let foreign = root.0.join("notes.txt");
    std::fs::write(&foreign, b"my holiday photos").expect("a file");

    let outcome = outcome_at(
        &root.0,
        Some(OutputFormat::Text),
        &args(DbAction::Import { path: foreign }),
    );
    assert!(matches!(outcome, CommandOutcome::Failed(_)), "{outcome:?}");
}
