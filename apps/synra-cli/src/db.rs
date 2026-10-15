//! `synra db` — the commands that read the database directly.
//!
//! # Why these do not go through the kernel
//!
//! Because they exist for the user whose kernel will not start. `db integrity` is what they run when they suspect
//! damage, and it would be useless if it needed a working kernel to answer — the same reason `doctor` reads the
//! directories rather than asking about them.
//!
//! # Why this module was missing
//!
//! The three subcommands were parsed, documented, and had argument tests — and every invocation ended in "this command
//! reads the database directly, which is not implemented yet". The store side already existed (`health` and the typed
//! readers); what was absent was this branch. A command a user can see and cannot run is worse than one that is not
//! there, because the first looks like a broken installation.

use synra_store::{Health, Paths, SynraDb};

use crate::args::{DbAction, DbArgs};
use crate::session::CommandOutcome;

/// Runs a `db` subcommand.
///
/// # Errors
///
/// Never. A failure is a [`CommandOutcome::Failed`], because every reason here — a database that will not open, damage,
/// a destination that exists — is something the user is meant to read and act on rather than a condition the caller
/// branches on.
#[must_use]
pub fn outcome(format: Option<crate::args::OutputFormat>, args: &DbArgs) -> CommandOutcome {
    outcome_at(&crate::session::data_root(), format, args)
}

/// The same, with the data root supplied.
///
/// # Why the root is a parameter
///
/// Because reading `SYNRA_DATA_DIR` is not testable from inside a process: `std::env::set_var` is `unsafe` in edition
/// 2024 — another thread may be reading the environment — and this workspace forbids `unsafe`. So the caller reads it and
/// the decision takes the value, which leaves the interesting part, what the command does with a database, testable
/// against a directory a test owns.
#[must_use]
pub fn outcome_at(
    root: &std::path::Path,
    format: Option<crate::args::OutputFormat>,
    args: &DbArgs,
) -> CommandOutcome {
    let paths = Paths::under(root);
    let opened = SynraDb::open(&paths.db_path()).and_then(|mut db| {
        db.migrate()?;
        Ok(db)
    });
    let db = match opened {
        Ok(db) => db,
        Err(error) => {
            // ★ Named the path as well as the reason. "Could not open the database" sends a user looking for a
            // permission problem in the wrong directory; the path is the one fact that makes it actionable.
            return CommandOutcome::Failed(format!(
                "{} could not be opened: {error}",
                paths.db_path().display()
            ));
        }
    };

    match &args.action {
        DbAction::Integrity => integrity(format, &db),
        DbAction::Backup { path } => backup(format, &db, path),
        DbAction::Dump { table } => dump(format, &db, table.as_deref()),
    }
}

/// Reports what the engine says about the database.
fn integrity(format: Option<crate::args::OutputFormat>, db: &SynraDb) -> CommandOutcome {
    let health = match db.health() {
        Ok(health) => health,
        Err(error) => return CommandOutcome::Failed(format!("the check could not run: {error}")),
    };

    match format {
        Some(crate::args::OutputFormat::Json) => {
            let value = serde_json::json!({
                "health": health_name(&health),
                "detail": health_detail(&health),
            });
            match health {
                // ★ `Sound` is `ok`, the other two are not. `Unknown` is not a pass: the check did not run, and a script
                // that read it as "fine" would be told the database is healthy by a check that never looked.
                Health::Sound => CommandOutcome::json(value.to_string()),
                _ => CommandOutcome::json_failure(value.to_string()),
            }
        }
        _ => match &health {
            Health::Sound => CommandOutcome::Lines(vec!["the database is sound".to_owned()]),
            Health::Corrupt { detail } => CommandOutcome::Failed(format!(
                "the database is damaged: {detail}\nrestore from a backup with `synra db backup` having been run before this happened"
            )),
            Health::Unknown { detail } => {
                CommandOutcome::Failed(format!("the check could not run: {detail}"))
            }
            // ★ `Health` is `#[non_exhaustive]`, so a variant added later is matched here rather than failing to
            // compile. It is reported as unknown rather than as sound: a state this build does not recognise is not a
            // pass, and saying "sound" would be the one answer that hides it.
            _ => CommandOutcome::Failed("the database reported a state this build does not recognise".to_owned()),
        },
    }
}

/// Writes a consistent copy of the database.
fn backup(
    format: Option<crate::args::OutputFormat>,
    db: &SynraDb,
    path: &std::path::Path,
) -> CommandOutcome {
    if let Err(error) = db.backup_to(path) {
        return CommandOutcome::Failed(error.to_string());
    }
    match format {
        Some(crate::args::OutputFormat::Json) => {
            CommandOutcome::json(serde_json::json!({ "written": path.display().to_string() }).to_string())
        }
        _ => CommandOutcome::Lines(vec![format!("wrote {}", path.display())]),
    }
}

/// Reads the tables a debugger wants.
///
/// # Why every table goes through one map
///
/// Because the single-table path and `all` answer the same question about the same six tables, and two lists would drift:
/// a table added to one and not the other is a `db dump --table x` that works while `db dump` silently omits it. The map
/// is the only list.
fn dump(format: Option<crate::args::OutputFormat>, db: &SynraDb, table: Option<&str>) -> CommandOutcome {
    let tables = |name: &str| -> Option<Result<serde_json::Value, String>> {
        match name {
            "identity" => Some(json(db.identity())),
            "devices" => Some(json(db.paired_devices())),
            "seen" => Some(json(db.seen_devices())),
            "plugins" => Some(json(db.plugins())),
            "grants" => Some(grants(db)),
            "config" => Some(json(db.config())),
            _ => None,
        }
    };
    const NAMES: [&str; 6] = ["identity", "devices", "seen", "plugins", "grants", "config"];

    let value = match table {
        // ★ An unknown table is refused rather than answered with an empty object. A dump that returned `{}` for a typo
        // would read as "this table is empty", which is a fact about the user's data rather than about their spelling.
        Some(other) => match tables(other) {
            Some(Ok(value)) => value,
            Some(Err(error)) => {
                return CommandOutcome::Failed(format!("{other} could not be read: {error}"));
            }
            None => {
                return CommandOutcome::Failed(format!(
                    "`{other}` is not a table this command knows; try {} or all",
                    NAMES.join(", ")
                ));
            }
        },
        // One object rather than a list of tables: the reader is a person with a JSON viewer, and the table name is the
        // useful key. A table that cannot be read is reported by name so the rest of the dump is still usable.
        None => {
            let mut all = serde_json::Map::new();
            for name in NAMES {
                match tables(name) {
                    Some(Ok(value)) => {
                        all.insert(name.to_owned(), value);
                    }
                    Some(Err(error)) => {
                        all.insert(name.to_owned(), serde_json::json!({ "error": error }));
                    }
                    None => {}
                }
            }
            serde_json::Value::Object(all)
        }
    };

    match format {
        Some(crate::args::OutputFormat::Json) => CommandOutcome::json(value.to_string()),
        // ★ Text output is the JSON anyway. A hand-written table renderer would be a second implementation of the same
        // facts, and the one thing `db dump` is for is being pasted into a bug report.
        _ => CommandOutcome::Lines(vec![value.to_string()]),
    }
}

/// Every plugin's decisions, keyed by plugin.
///
/// `plugin_grants` takes one identifier, so a dump of the table is one read per plugin. That is a deliberate shape
/// rather than a gap: the table is keyed by `(plugin_id, capability)` and a reader asking about one plugin is the
/// ordinary case, so the query that exists is the one the rest of the system makes.
fn grants(db: &SynraDb) -> Result<serde_json::Value, String> {
    let plugins = db.plugins().map_err(|error| error.to_string())?;
    let mut by_plugin = serde_json::Map::new();
    for plugin in plugins {
        let rows = db.plugin_grants(&plugin.plugin_id).map_err(|error| error.to_string())?;
        let value = serde_json::to_value(rows).map_err(|error| error.to_string())?;
        by_plugin.insert(plugin.plugin_id.clone(), value);
    }
    Ok(serde_json::Value::Object(by_plugin))
}

/// Serialises a reader's answer, reporting a failure as text.
fn json<T: serde::Serialize>(rows: Result<T, synra_store::DbError>) -> Result<serde_json::Value, String> {
    let rows = rows.map_err(|error| error.to_string())?;
    serde_json::to_value(rows).map_err(|error| error.to_string())
}

/// The name of a health result, for JSON.
const fn health_name(health: &Health) -> &'static str {
    match health {
        Health::Sound => "sound",
        Health::Corrupt { .. } => "corrupt",
        Health::Unknown { .. } => "unknown",
        _ => "unrecognised",
    }
}

/// What a health result says, when it says anything.
fn health_detail(health: &Health) -> Option<&str> {
    match health {
        Health::Sound => None,
        Health::Corrupt { detail } | Health::Unknown { detail } => Some(detail),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{DbAction, OutputFormat};

    /// A directory that removes itself, so a failing test does not leave a database behind.
    struct Root(std::path::PathBuf);

    impl Root {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-db-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a directory");
            Self(path)
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn args(action: DbAction) -> DbArgs {
        DbArgs { action }
    }

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
}
