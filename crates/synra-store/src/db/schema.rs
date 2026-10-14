//! Why an operation failed, and what may be applied.

use super::migrations::{MIGRATIONS, Migration};
use super::state::{SchemaState, schema_state};
/// Why a schema operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaError {
    /// The database is newer than this build.
    #[error(
        "the database is at schema version {found} and this build understands {known}; \
         a newer version of the application wrote it"
    )]
    TooNew {
        /// The version found.
        found: u32,
        /// The version this build understands.
        known: u32,
    },

    /// The migration list is not a sequence from one upwards.
    #[error("the migration list is malformed: {0}")]
    MalformedList(&'static str),

    /// A statement failed.
    #[error("migration {version} ({name}) failed at statement {index}: {detail}")]
    StatementFailed {
        /// The migration's version.
        version: u32,
        /// Its name.
        name: &'static str,
        /// Which statement, counting from zero.
        index: usize,
        /// What the engine said.
        detail: String,
    },

    /// The integrity check found a problem.
    #[error("the database failed its integrity check: {0}")]
    Corrupt(String),
}

/// Checks the migration list is a sequence from one upwards with no gaps or repeats.
///
/// A gap would mean a version whose shape nobody defined, and an engine that applies steps in order would
/// silently skip from one shape to a different one. Caught here rather than at the first device that runs it.
///
/// # Errors
///
/// [`SchemaError::MalformedList`] describing the first problem.
pub fn check_migration_list(migrations: &[Migration]) -> Result<(), SchemaError> {
    for (index, migration) in migrations.iter().enumerate() {
        // The version is the position plus one, so the list cannot have a gap or a duplicate by construction.
        let expected = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        if migration.version != expected {
            return Err(SchemaError::MalformedList(
                "a migration's version must be its position plus one",
            ));
        }
        if migration.name.is_empty() {
            return Err(SchemaError::MalformedList("a migration must have a name"));
        }
        if migration.statements.is_empty() {
            return Err(SchemaError::MalformedList("a migration must have at least one statement"));
        }
    }
    Ok(())
}

/// What a migration run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationOutcome {
    /// The versions applied, in order.
    pub applied: Vec<u32>,
    /// The version reached.
    pub version: u32,
}

impl MigrationOutcome {
    /// Whether anything ran.
    #[must_use]
    pub const fn changed_anything(&self) -> bool {
        !self.applied.is_empty()
    }

    /// A sentence for the log.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.applied.is_empty() {
            return format!("schema already at version {}", self.version);
        }
        format!(
            "applied {} migration(s) to reach schema version {}",
            self.applied.len(),
            self.version
        )
    }
}

/// Runs the pending migrations through a caller-supplied executor.
///
/// The executor is a closure rather than a connection, so the ordering, the refusal of a too-new database and
/// the failure behaviour are all testable without a database engine. The application layer passes a closure that
/// runs the statement through `rusqlite`.
///
/// # Errors
///
/// [`SchemaError::TooNew`] if the database is newer, or [`SchemaError::StatementFailed`] if the executor
/// refused a statement. A failed migration leaves the recorded version at the last one that succeeded, so the
/// next run resumes rather than repeating a step that already ran.
pub fn apply(
    recorded: Option<u32>,
    execute: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<MigrationOutcome, SchemaError> {
    check_migration_list(MIGRATIONS)?;

    let state = schema_state(recorded);
    if let SchemaState::Newer { found, known } = state {
        return Err(SchemaError::TooNew { found, known });
    }

    let mut outcome = MigrationOutcome {
        version: match state {
            SchemaState::At { version } => version,
            _ => 0,
        },
        applied: Vec::new(),
    };

    for migration in state.pending() {
        for (index, statement) in migration.statements.iter().enumerate() {
            execute(statement).map_err(|detail| SchemaError::StatementFailed {
                version: migration.version,
                name: migration.name,
                index,
                detail,
            })?;
        }
        outcome.applied.push(migration.version);
        outcome.version = migration.version;
    }

    Ok(outcome)
}
