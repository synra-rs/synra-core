//! The `.synrabackup` container: a zip of the database, its configuration, and what was installed.
//!
//! # Why a container rather than just the database file
//!
//! Because a database restore answers "what did this device know", and the two questions a user asks next are "what was
//! switched on" and "what do I reinstall". The database carries both, but a backup that a person can open and read — a
//! config file and a plugin list in plain JSON — is one they can inspect before trusting it with a restore.
//!
//! # Why the database inside is a `VACUUM INTO` copy
//!
//! For the same reason [`SynraDb::backup_to`](super::SynraDb::backup_to) exists: a live database has a write-ahead log,
//! and copying the main file produces a database that may not open. The copy inside the container is the same consistent
//! artifact `synra db backup` writes, not a second, weaker mechanism.
//!
//! # What importing does **not** do
//!
//! It does not reinstall plugins. The artifacts are deliberately not in the backup (the design says they come from the
//! registry), so the import answers with the list that needs reinstalling and leaves the decision to the user.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::db::Health;
use crate::sqlite::{DbError, SynraDb, restore_from};

/// The marker in `manifest.json` that says this is one of ours.
pub const FORMAT: &str = "synra.backup";

/// The container version this build writes and the only one it reads.
///
/// # Why reading an older version is refused rather than migrated
///
/// Because there is no older version yet. A version check that quietly accepted "whatever" would be a promise the first
/// real format change would break; refusing an unknown version is the answer that stays true.
pub const VERSION: u32 = 1;

/// The entries every container has.
pub const ENTRIES: [&str; 4] = ["manifest.json", "config.json", "plugins-manifest.json", "kernel.db"];

/// What `manifest.json` says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupManifest {
    /// [`FORMAT`], so a zip of something else is recognised as not a backup.
    pub format: String,
    /// [`VERSION`].
    pub version: u32,
    /// When the container was written, in Unix milliseconds.
    pub created_ms: i64,
    /// The entries the container holds, so a reader knows before opening them.
    pub includes: Vec<String>,
}

/// One plugin a restored device will have to reinstall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginEntry {
    /// The plugin.
    pub plugin_id: String,
    /// The version that was active, when the store knew one.
    pub version: Option<String>,
    /// Whether it was switched on.
    pub enabled: bool,
}

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    /// How many plugins the container lists.
    pub plugins: usize,
    /// The size of the container on disk.
    pub bytes: u64,
}

/// What an import brought back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedBackup {
    /// The plugins that were installed, and now need reinstalling.
    pub plugins: Vec<PluginEntry>,
    /// Where the replaced database was kept, if there was one.
    pub previous: Option<PathBuf>,
}

/// Why the container could not be written or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// A file operation failed.
    #[error("the backup file could not be used: {detail}")]
    Io {
        /// What the operating system said.
        detail: String,
    },
    /// The zip container is malformed.
    #[error("the backup is not a readable zip: {0}")]
    Zip(#[from] ZipError),
    /// The manifest or one of the JSON entries is malformed.
    #[error("the backup's JSON is malformed: {detail}")]
    Json {
        /// What the parser said.
        detail: String,
    },
    /// The database inside could not be copied or restored.
    #[error("the database inside the backup could not be used: {0}")]
    Store(#[from] DbError),
    /// An entry the container promises is absent.
    #[error("the backup does not contain {0}")]
    Missing(&'static str),
    /// The destination already exists.
    #[error("{} already exists; a backup does not overwrite one", .0.display())]
    DestinationExists(PathBuf),
    /// The container is a backup, but a newer one.
    #[error("the backup is version {found}, and this build reads version {expected}")]
    UnsupportedVersion {
        /// What the container says.
        found: u32,
        /// What this build writes.
        expected: u32,
    },
    /// The zip is not a Synra backup at all.
    #[error("{0:?} is not a Synra backup")]
    Format(String),
}

// ★ Conversions are private helpers rather than `From` impls: a public error enum that converts `std::io::Error` or
// `serde_json::Error` makes this crate's public surface a promise about those crates' versions. What a caller acts on
// is the variant.

/// Writes a container of `db` to `destination`, which must not exist.
///
/// # Errors
///
/// [`BackupError::DestinationExists`] when the file is already there — the caller is usually a user making a backup before
/// something risky, and this code cannot know whether the file there is the one they meant to keep. Every other variant
/// names the step that failed.
pub fn export_backup(
    db: &SynraDb,
    destination: &Path,
    created_ms: i64,
) -> Result<BackupSummary, BackupError> {
    if destination.exists() {
        return Err(BackupError::DestinationExists(destination.to_path_buf()));
    }

    // The database copy is written beside the container and removed afterwards: a temporary file in the same directory is
    // what makes the rename/copy cheap, and the container is the only artifact a user should find afterwards.
    let kernel = temp_sibling(destination, "kernel");
    let result = write_container(db, destination, &kernel, created_ms);
    let _ = std::fs::remove_file(&kernel);
    if result.is_err() {
        // A half-written container is worse than none: the next attempt would find a destination that exists.
        let _ = std::fs::remove_file(destination);
    }
    result
}

/// The bytes of the container: manifest, configuration, plugin list, database.
fn write_container(
    db: &SynraDb,
    destination: &Path,
    kernel: &Path,
    created_ms: i64,
) -> Result<BackupSummary, BackupError> {
    db.backup_to(kernel)?;
    let plugins: Vec<PluginEntry> = db
        .plugins()?
        .into_iter()
        .map(|row| PluginEntry {
            // A version that cannot be read is not a reason to fail the whole backup: the list is about reinstalling, and
            // `None` says "the store did not know", which is true.
            version: db
                .active_plugin_version(&row.plugin_id)
                .ok()
                .flatten()
                .map(|(version, _)| version),
            enabled: row.enabled,
            plugin_id: row.plugin_id,
        })
        .collect();
    let manifest = BackupManifest {
        format: FORMAT.to_owned(),
        version: VERSION,
        created_ms,
        includes: ENTRIES.iter().map(|name| (*name).to_owned()).collect(),
    };
    let config = config_document(db)?;

    let file = std::fs::File::create(destination).map_err(|error| BackupError::Io { detail: error.to_string() })?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zip.start_file("manifest.json", options)?;
    zip.write_all(&serde_json::to_vec_pretty(&manifest).map_err(|error| BackupError::Json { detail: error.to_string() })?)
        .map_err(|error| BackupError::Io { detail: error.to_string() })?;
    zip.start_file("config.json", options)?;
    zip.write_all(&serde_json::to_vec_pretty(&config).map_err(|error| BackupError::Json { detail: error.to_string() })?)
        .map_err(|error| BackupError::Io { detail: error.to_string() })?;
    zip.start_file("plugins-manifest.json", options)?;
    zip.write_all(&serde_json::to_vec_pretty(&plugins).map_err(|error| BackupError::Json { detail: error.to_string() })?)
        .map_err(|error| BackupError::Io { detail: error.to_string() })?;
    zip.start_file("kernel.db", options)?;
    let mut database = std::fs::File::open(kernel).map_err(|error| BackupError::Io { detail: error.to_string() })?;
    std::io::copy(&mut database, &mut zip).map_err(|error| BackupError::Io { detail: error.to_string() })?;
    zip.finish()?;

    Ok(BackupSummary {
        plugins: plugins.len(),
        bytes: std::fs::metadata(destination).map_err(|error| BackupError::Io { detail: error.to_string() })?.len(),
    })
}

/// The configuration as a JSON object, one key per dotted path.
fn config_document(db: &SynraDb) -> Result<serde_json::Value, BackupError> {
    let mut document = serde_json::Map::new();
    for row in db.config()? {
        // The store writes JSON text, but a row edited by hand is still a row a backup should carry: unparseable text is
        // exported as a string rather than failing the export, which would make a damaged setting block every backup.
        let value = serde_json::from_str(&row.value)
            .unwrap_or_else(|_| serde_json::Value::String(row.value.clone()));
        document.insert(row.key, value);
    }
    Ok(serde_json::Value::Object(document))
}

/// Reads a container and replaces `database` with the copy inside it.
///
/// The database is validated by [`restore_from`]: sound, readable, and not from a newer schema. The plugin list is returned
/// rather than acted on — the artifacts are not in the container, so reinstalling is the user's next decision.
///
/// # Errors
///
/// [`BackupError`] when the container is not a backup, is a version this build does not read, is malformed, or when the
/// database it holds cannot be restored.
pub fn import_backup(archive: &Path, database: &Path) -> Result<ImportedBackup, BackupError> {
    let file = std::fs::File::open(archive).map_err(|error| BackupError::Io { detail: error.to_string() })?;
    let mut zip = ZipArchive::new(file)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&read_entry(&mut zip, "manifest.json")?).map_err(|error| BackupError::Json { detail: error.to_string() })?;
    if manifest.format != FORMAT {
        return Err(BackupError::Format(manifest.format));
    }
    if manifest.version != VERSION {
        return Err(BackupError::UnsupportedVersion { found: manifest.version, expected: VERSION });
    }
    let plugins: Vec<PluginEntry> =
        serde_json::from_slice(&read_entry(&mut zip, "plugins-manifest.json")?)
            .map_err(|error| BackupError::Json { detail: error.to_string() })?;

    // Extract beside the live database: `restore_from` renames the current one in the same directory, and a temporary file
    // on another volume would have to be copied rather than renamed.
    let extracted = temp_sibling(database, "importing");
    let _ = std::fs::remove_file(&extracted);
    let result = extract_kernel(&mut zip, &extracted).and_then(|()| {
        restore_from(&extracted, database).map_err(BackupError::Store)
    });
    let _ = std::fs::remove_file(&extracted);
    let report = result?;
    Ok(ImportedBackup { plugins, previous: report.previous })
}

/// Copies `kernel.db` out of the archive, then checks it is a sound database before anything replaces the live one.
fn extract_kernel(zip: &mut ZipArchive<std::fs::File>, path: &Path) -> Result<(), BackupError> {
    {
        let mut entry = zip
            .by_name("kernel.db")
            .map_err(|error| match error {
                ZipError::FileNotFound => BackupError::Missing("kernel.db"),
                other => BackupError::Zip(other),
            })?;
        let mut out = std::fs::File::create(path).map_err(|error| BackupError::Io { detail: error.to_string() })?;
        std::io::copy(&mut entry, &mut out).map_err(|error| BackupError::Io { detail: error.to_string() })?;
    }
    // `restore_from` opens the file read-only and runs the integrity check, so this is where a damaged database inside a
    // valid container is caught — before the rename, as always.
    let checked = SynraDb::open_read_only(path)?;
    match checked.health()? {
        Health::Sound => Ok(()),
        other => Err(BackupError::Store(DbError::Statement {
            why: format!("the database inside the backup is not sound ({other:?})"),
        })),
    }
}

/// One entry's bytes, naming a missing entry as such rather than as a corrupt zip.
fn read_entry(
    zip: &mut ZipArchive<std::fs::File>,
    name: &'static str,
) -> Result<Vec<u8>, BackupError> {
    let mut entry = zip.by_name(name).map_err(|error| match error {
        ZipError::FileNotFound => BackupError::Missing(name),
        other => BackupError::Zip(other),
    })?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).map_err(|error| BackupError::Io { detail: error.to_string() })?;
    Ok(bytes)
}

/// A path beside `path` with a suffix, so the temporary file lives in the same directory.
fn temp_sibling(path: &Path, suffix: &str) -> PathBuf {
    let name = path
        .file_name()
        .map_or_else(|| "synra-backup".to_owned(), |name| name.to_string_lossy().into_owned());
    path.with_file_name(format!("{name}.{suffix}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-backup-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        fn db(&self) -> PathBuf {
            self.0.join("synra.db")
        }

        fn archive(&self) -> PathBuf {
            self.0.join("copy.synrabackup")
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
    fn an_export_lists_the_four_entries_and_an_import_brings_the_data_back() {
        let scratch = Scratch::new("round-trip");
        let database = scratch.db();
        let archive = scratch.archive();
        let db = migrated(&database);
        db.set_config("test.key", &serde_json::json!("from the backup"), 1)
            .expect("written");
        db.insert_plugin("@acme/hello", true, true, "healthy", 1, 1).expect("inserted");

        let summary = export_backup(&db, &archive, 1_700_000_000_000).expect("exports");
        assert_eq!(summary.plugins, 1);

        {
            let file = std::fs::File::open(&archive).expect("the container");
            let mut zip = ZipArchive::new(file).expect("a zip");
            for name in ENTRIES {
                assert!(zip.by_name(name).is_ok(), "{name} is missing");
            }
            let manifest: BackupManifest = serde_json::from_slice(
                &read_entry(&mut zip, "manifest.json").expect("the manifest"),
            )
            .expect("manifest JSON");
            assert_eq!(manifest.format, FORMAT);
            assert_eq!(manifest.version, VERSION);
            assert_eq!(manifest.created_ms, 1_700_000_000_000);
        }

        // The live database changes, so the import is observable rather than a no-op.
        db.set_config("test.key", &serde_json::json!("changed after"), 2)
            .expect("written");
        drop(db);

        let imported = import_backup(&archive, &database).expect("imports");
        assert_eq!(imported.plugins.len(), 1);
        assert_eq!(imported.plugins[0].plugin_id, "@acme/hello");
        assert_eq!(imported.plugins[0].version, None, "no version was recorded");
        let previous = imported.previous.expect("the replaced database was kept");
        assert!(previous.exists());

        let restored = SynraDb::open(&database).expect("the restored database opens");
        let config = restored.config().expect("reads");
        assert_eq!(
            config
                .iter()
                .find(|row| row.key == "test.key")
                .map(|row| serde_json::from_str::<serde_json::Value>(&row.value).expect("JSON text")),
            Some(serde_json::json!("from the backup"))
        );
        assert_eq!(restored.plugins().expect("reads").len(), 1);
    }

    #[test]
    fn an_export_refuses_to_overwrite_a_container() {
        let scratch = Scratch::new("exists");
        let database = scratch.db();
        let archive = scratch.archive();
        let db = migrated(&database);
        std::fs::write(&archive, b"something the user put here").expect("a file");

        let error = export_backup(&db, &archive, 1).expect_err("a destination that exists is refused");
        assert!(matches!(error, BackupError::DestinationExists(_)), "{error}");
        assert_eq!(
            std::fs::read(&archive).expect("still there"),
            b"something the user put here",
            "the file was touched"
        );
    }

    #[test]
    fn a_foreign_or_newer_container_is_refused_before_anything_is_replaced() {
        // ★ Two refusals with one property: the live database is untouched. A container is a file from somewhere else, and
        // "somewhere else" includes a zip of holiday photos.
        let scratch = Scratch::new("foreign");
        let database = scratch.db();
        let archive = scratch.archive();
        let db = migrated(&database);
        db.set_config("test.key", &serde_json::json!("current"), 1).expect("written");
        drop(db);

        let mut foreign = std::fs::File::create(&archive).expect("a file");
        let mut zip = ZipWriter::new(&mut foreign);
        zip.start_file("manifest.json", SimpleFileOptions::default()).expect("an entry");
        zip.write_all(br#"{"format":"holiday.photos","version":1,"createdMs":0,"includes":[]}"#)
            .expect("written");
        zip.finish().expect("a zip");
        drop(foreign);
        let error = import_backup(&archive, &database).expect_err("a foreign container is refused");
        assert!(matches!(error, BackupError::Format(_)), "{error}");

        std::fs::remove_file(&archive).expect("removed");
        let mut newer = std::fs::File::create(&archive).expect("a file");
        let mut zip = ZipWriter::new(&mut newer);
        zip.start_file("manifest.json", SimpleFileOptions::default()).expect("an entry");
        zip.write_all(
            format!(r#"{{"format":"{FORMAT}","version":99,"createdMs":0,"includes":[]}}"#).as_bytes(),
        )
        .expect("written");
        zip.finish().expect("a zip");
        drop(newer);
        let error = import_backup(&archive, &database).expect_err("a newer container is refused");
        assert!(
            matches!(error, BackupError::UnsupportedVersion { found: 99, expected: VERSION }),
            "{error}"
        );

        let current = SynraDb::open(&database).expect("the database still opens");
        let config = current.config().expect("reads");
        assert_eq!(
            config
                .iter()
                .find(|row| row.key == "test.key")
                .map(|row| serde_json::from_str::<serde_json::Value>(&row.value).expect("JSON text")),
            Some(serde_json::json!("current")),
            "a refused import changed the database"
        );
    }
}
