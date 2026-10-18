//! Putting a backup back, safely.
//!
//! # Why this is in the store
//!
//! Because it is four filesystem decisions in a row — where the old database goes, which sidecars must not survive, whether
//! the copy opens — and the CLI is not the only caller that might ever need them. The store owns the file, so the store
//! owns the operation that replaces it.
//!
//! # Why the old file is kept
//!
//! Because the reason to restore is usually that the current database is damaged, and "damaged" is a diagnosis made by a
//! program. Keeping the file costs its size and gives a user a way back from a wrong diagnosis; deleting it makes the
//! restore a one-way door taken by a tool that can be wrong.

use std::path::{Path, PathBuf};

use crate::db::Health;

use super::{DbError, SynraDb};

/// What a restore did with the database that was there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Where the replaced database was kept, when there was one to replace.
    pub previous: Option<PathBuf>,
}

/// Replaces `database` with the file at `backup`.
///
/// # What is checked before anything is touched
///
/// The backup is opened **read-only**, must pass the integrity check, and must not be from a newer schema. A restore that
/// copied first and checked afterwards would have destroyed the only copy of the current data on the strength of a file it
/// had not opened.
///
/// # Errors
///
/// [`DbError`] when the backup cannot be opened, is damaged, is from a newer build, or when the filesystem refuses a step.
/// Every failure after the rename puts the previous database back.
pub fn restore_from(backup: &Path, database: &Path) -> Result<RestoreReport, DbError> {
    // 1. Inspect the file we are about to copy, without writing to it.
    {
        let checked = SynraDb::open_read_only(backup)?;
        match checked.health()? {
            Health::Sound => {}
            other => {
                return Err(DbError::Statement {
                    why: format!(
                        "the backup {} is not sound ({other:?}); restoring it would replace a working database with a damaged file",
                        backup.display()
                    ),
                });
            }
        }
    }

    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(|error| DbError::Statement {
            why: format!("the directory {} cannot be created: {error}", parent.display()),
        })?;
    }

    // 2. Keep what is there. The timestamp makes a second restore beside the first, rather than over it.
    let previous = database.exists().then(|| unique_previous(database)).transpose()?;
    // 3. The old write-ahead log belongs to the old file. Replaying it against the copy would corrupt the copy.
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(database, suffix));
    }

    // 4. Copy, then prove the copy opens and is sound. A failed copy or a bad verification is undone.
    if let Err(error) = std::fs::copy(backup, database) {
        let failure = DbError::Statement {
            why: format!("the backup could not be copied onto {}: {error}", database.display()),
        };
        return Err(rollback(database, &previous, failure));
    }
    match SynraDb::open(database) {
        Ok(copy) => match copy.health() {
            Ok(Health::Sound) => {}
            Ok(other) => {
                return Err(rollback(
                    database,
                    &previous,
                    DbError::Statement {
                        why: format!("the restored copy is not sound ({other:?})"),
                    },
                ));
            }
            Err(error) => return Err(rollback(database, &previous, error)),
        },
        Err(error) => return Err(rollback(database, &previous, error)),
    }

    Ok(RestoreReport { previous })
}

/// A path beside the database that no earlier restore has taken.
fn unique_previous(database: &Path) -> Result<PathBuf, DbError> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    let name = database
        .file_name()
        .map_or_else(|| "synra.db".to_owned(), |name| name.to_string_lossy().into_owned());
    let kept = database.with_file_name(format!("{name}.before-restore-{stamp}"));
    std::fs::rename(database, &kept).map_err(|error| DbError::Statement {
        why: format!(
            "the current database could not be moved aside to {}: {error}",
            kept.display()
        ),
    })?;
    Ok(kept)
}

/// Puts the previous database back after a failed restore.
fn rollback(database: &Path, previous: &Option<PathBuf>, error: DbError) -> DbError {
    let _ = std::fs::remove_file(database);
    if let Some(kept) = previous {
        let _ = std::fs::rename(kept, database);
    }
    error
}

/// The write-ahead log or shared-memory file that belongs to a database path.
fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-restore-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        fn db(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn migrated(path: &Path) -> SynraDb {
        let mut db = SynraDb::open(path).expect("opens");
        db.migrate().expect("migrates");
        db
    }

    #[test]
    fn a_restore_brings_the_backup_back_and_keeps_what_it_replaced() {
        // ★ The point of the command: a user whose database is damaged restores a backup, and the file that was there is
        // still on disk — the diagnosis may have been wrong, and the tool must not be the last word on it.
        let scratch = Scratch::new("round-trip");
        let database = scratch.db("synra.db");
        let backup = scratch.db("before.db");
        {
            let db = migrated(&database);
            db.set_config("test.key", &serde_json::json!("from the backup"), 1)
                .expect("written");
            db.backup_to(&backup).expect("a backup");
            // And then the live database changes, so the restore is observable rather than a no-op.
            db.set_config("test.key", &serde_json::json!("changed after"), 2)
                .expect("written");
        }

        let report = restore_from(&backup, &database).expect("restores");
        let previous = report.previous.expect("the old database was kept");
        assert!(previous.exists(), "the replaced database is still there");
        assert_ne!(previous, database);

        let db = SynraDb::open(&database).expect("the restored database opens");
        let config = db.config().expect("reads");
        assert_eq!(
            config
                .iter()
                .find(|row| row.key == "test.key")
                .map(|row| serde_json::from_str::<serde_json::Value>(&row.value).expect("JSON text")),
            Some(serde_json::json!("from the backup"))
        );
    }

    #[test]
    fn a_damaged_backup_is_refused_and_the_current_database_is_untouched() {
        // ★ Validation happens before the rename. A restore that copied first would destroy the working file on the
        // strength of a backup it had not opened.
        let scratch = Scratch::new("damaged");
        let database = scratch.db("synra.db");
        let backup = scratch.db("damaged.db");
        let db = migrated(&database);
        db.set_config("test.key", &serde_json::json!("current"), 1).expect("written");
        std::fs::write(&backup, b"this is not a database").expect("the damaged file");

        let error = restore_from(&backup, &database).expect_err("a damaged backup is refused");
        assert!(error.to_string().contains("damaged") || error.to_string().contains("not a database"), "{error}");

        let db = SynraDb::open(&database).expect("the current database still opens");
        let config = db.config().expect("reads");
        assert_eq!(
            config
                .iter()
                .find(|row| row.key == "test.key")
                .map(|row| serde_json::from_str::<serde_json::Value>(&row.value).expect("JSON text")),
            Some(serde_json::json!("current")),
            "the current database was replaced by a file that could not be opened"
        );
    }

    #[test]
    fn restoring_where_there_is_no_database_keeps_nothing() {
        let scratch = Scratch::new("fresh");
        let database = scratch.db("synra.db");
        let backup = scratch.db("backup.db");
        {
            let db = migrated(&backup);
            db.set_config("test.key", &serde_json::json!(1), 1).expect("written");
        }

        let report = restore_from(&backup, &database).expect("restores");
        assert_eq!(report.previous, None, "there was nothing to keep");
        assert!(database.exists());
    }
}
