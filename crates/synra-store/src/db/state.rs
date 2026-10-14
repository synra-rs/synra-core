//! Which version a database is at.

use super::migrations::{MIGRATIONS, Migration, latest_version};
/// Which version a database is at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaState {
    /// A fresh database. Nothing has been applied.
    Empty,
    /// Some steps have been applied.
    At {
        /// The version found.
        version: u32,
    },
    /// The database is newer than this build.
    ///
    /// Refused rather than migrated: a device that ran a newer build and then an older one — a downgrade, or two
    /// installations sharing a directory — has a schema whose columns this build does not know about. Running
    /// its own migrations would leave the shape neither version expects.
    Newer {
        /// The version found.
        found: u32,
        /// The version this build understands.
        known: u32,
    },
}

impl SchemaState {
    /// Whether the database can be opened.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        !matches!(self, Self::Newer { .. })
    }

    /// The steps needed to reach this build's version.
    #[must_use]
    pub fn pending(self) -> Vec<&'static Migration> {
        let from = match self {
            Self::Empty => 0,
            Self::At { version } => version,
            // Nothing is pending for a database this build cannot understand; the caller refuses instead.
            Self::Newer { .. } => return Vec::new(),
        };
        MIGRATIONS
            .iter()
            .filter(|migration| migration.version > from)
            .collect()
    }
}

/// Decides what a recorded version means.
#[must_use]
pub fn schema_state(recorded: Option<u32>) -> SchemaState {
    match recorded {
        None => SchemaState::Empty,
        Some(0) => SchemaState::Empty,
        Some(version) if version > latest_version() => {
            SchemaState::Newer { found: version, known: latest_version() }
        }
        Some(version) => SchemaState::At { version },
    }
}
