//! Backup data models and structured errors.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zip::result::ZipError;

use crate::sqlite::DbError;

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
    /// Where the package came from on the device that made the container, when the install recorded it.
    ///
    /// # Why this is in the plugin list
    ///
    /// Because the design's restore flow ends with "reinstall these", and a list of identifiers is not an instruction.
    /// The installer writes a `source.json` beside the artifact; this carries what it says, so the import can tell a user
    /// which file or directory to install again. `None` is honest: an older install, or a container written before the
    /// note existed, does not know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The capabilities the user had allowed, in the order they were decided.
    ///
    /// # Why consent travels with a backup
    ///
    /// Because reinstalling clears the row, and the grants cascade with it: without this list every restored plugin would
    /// ask the same questions again. The list is what the user **approved**, not what the manifest declares — a denied
    /// capability is absent rather than present with `false`, because the question a restore asks is "what may it do".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<String>,
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


