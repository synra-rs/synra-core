use std::io::Write as _;
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::SynraDb;

use super::{
    BackupError, BackupManifest, ENTRIES, FORMAT, VERSION, export_backup, import_backup,
    plugins_in_backup, read_entry,
};

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
    db.record_grants(
        "@acme/hello",
        &[("log:*".to_owned(), true), ("net:read-title".to_owned(), false)],
        1,
        "manifest-digest",
    )
    .expect("grants recorded");
    // The note an install writes beside the artifact; the container is supposed to carry it.
    let plugins_dir = scratch.0.join("plugins");
    std::fs::create_dir_all(plugins_dir.join("@acme/hello")).expect("a plugin directory");
    std::fs::write(
        plugins_dir.join("@acme/hello").join("source.json"),
        br#"{"path":"/tmp/packages/hello","installedAtMs":1}"#,
    )
    .expect("the source note");

    let summary = export_backup(&db, &plugins_dir, &archive, 1_700_000_000_000).expect("exports");
    assert_eq!(summary.plugins, 1);
    // ★ The reinstall command reads this list without restoring: the import needs the kernel stopped, and reinstalling
    // needs it running, so the two are separate acts over one file.
    let listed = plugins_in_backup(&archive).expect("lists the plugins");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].source.as_deref(), Some("/tmp/packages/hello"));
    // ★ Only what was allowed travels: a denied capability is absence, not a `false` the restore would have to read.
    assert_eq!(listed[0].grants, vec!["log:*".to_owned()]);

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
    assert_eq!(
        imported.plugins[0].source.as_deref(),
        Some("/tmp/packages/hello"),
        "the container did not carry where the package came from"
    );
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

    let error = export_backup(&db, &scratch.0.join("plugins"), &archive, 1)
        .expect_err("a destination that exists is refused");
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
