//! The database: the migration sequence, the pragmas, and the health checks.
//!
//! # Migrations only ever add
//!
//! A published migration is never edited. Somebody's device has already run it, and an edited one either runs
//! again — producing a schema that is neither the old shape nor the new one — or is skipped because its version
//! is recorded, leaving that device on a shape no code was written for.
//!
//! So the sequence is a list of append-only steps, and a destructive change is a *new* step that copies rather
//! than an edit to an old one. The design document calls for such a step to be a separate, optional `compact`
//! operation; this module's shape supports that by making each step a value rather than a line of code.
//!
//! # The checks run here, not in the caller
//!
//! `integrity_check` on start-up, and the pragmas that the rest of the system assumes. A caller that forgot
//! `foreign_keys = ON` would get a database that silently accepts orphaned rows, and the failure would surface
//! as data that cannot be joined rather than as an error.
//!
//! # This is not a SQLite binding
//!
//! The design document names `rusqlite` and `rusqlite_migration`. Neither is used here, deliberately: the
//! migration *logic* — the ordering, the versioning, the failure behaviour — is testable without a database
//! engine, and a crate whose whole job is to hold the kernel's persistence contract should not carry a C
//! dependency to be checked. [`Migration`] is what the application layer hands to the binding, and
//! [`apply`] is the reference implementation the binding's behaviour is compared against.

use core::fmt;

/// One schema step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The version this step produces, counting from one.
    pub version: u32,
    /// A short name, for a log line.
    pub name: &'static str,
    /// The statements, run in order.
    pub statements: &'static [&'static str],
}

/// The statements that create the schema, in order.
///
/// Five steps, matching the design document's table list. Split by area rather than by table so that a step is
/// one coherent change: an interrupted migration then leaves the database at a version whose shape is one
/// somebody reasoned about, rather than halfway through adding a column.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        statements: &[
            // The device's own identity. One row, enforced by the primary key being a constant.
            "CREATE TABLE identity (
                id            INTEGER PRIMARY KEY CHECK (id = 1),
                device_id     TEXT NOT NULL,
                display_name  TEXT NOT NULL,
                platform      TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            )",
            // Paired devices, with the features the peer announced at pairing time so a link can be set up
            // without re-negotiating.
            "CREATE TABLE paired_devices (
                device_id     TEXT PRIMARY KEY,
                display_name  TEXT NOT NULL,
                platform      TEXT NOT NULL,
                features      TEXT NOT NULL DEFAULT '[]',
                paired_at_ms  INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL DEFAULT 0,
                blocked       INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1))
            )",
            // Devices heard from, for name caching and ordering. Cacheable: losing it costs a rediscovery.
            "CREATE TABLE devices_seen (
                device_id     TEXT PRIMARY KEY,
                display_name  TEXT NOT NULL,
                platform      TEXT NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                source        TEXT NOT NULL
            )",
            // The configuration. Keyed by a dotted path so a nested structure round-trips through one table.
            "CREATE TABLE config (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_ms INTEGER NOT NULL
            )",
        ],
    },
    Migration {
        version: 2,
        name: "plugins",
        statements: &[
            "CREATE TABLE plugins (
                plugin_id       TEXT PRIMARY KEY,
                enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                trusted         INTEGER NOT NULL DEFAULT 0 CHECK (trusted IN (0, 1)),
                health          TEXT NOT NULL DEFAULT 'unknown',
                installed_at_ms INTEGER NOT NULL,
                updated_at_ms   INTEGER NOT NULL
            )",
            // One row per version, so an upgrade keeps the previous artifact until the new one is confirmed.
            "CREATE TABLE plugin_versions (
                plugin_id    TEXT NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
                version      TEXT NOT NULL,
                artifact     TEXT NOT NULL,
                digest       TEXT NOT NULL,
                manifest     TEXT NOT NULL,
                installed_ms INTEGER NOT NULL,
                active       INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
                PRIMARY KEY (plugin_id, version)
            )",
            // The grants, with the manifest fingerprint they were approved against. The fingerprint is what
            // makes an upgrade ask again: a manifest whose capability list changed is not the one the user
            // agreed to, and comparing digests is how that is noticed without showing every permission again.
            "CREATE TABLE plugin_grants (
                plugin_id       TEXT NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
                capability      TEXT NOT NULL,
                granted         INTEGER NOT NULL CHECK (granted IN (0, 1)),
                decided_ms      INTEGER NOT NULL,
                manifest_digest TEXT NOT NULL,
                PRIMARY KEY (plugin_id, capability)
            )",
            "CREATE TABLE plugin_actions (
                plugin_id   TEXT NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
                name        TEXT NOT NULL,
                args_schema TEXT,
                description TEXT,
                PRIMARY KEY (plugin_id, name)
            )",
            "CREATE TABLE plugin_deps (
                plugin_id     TEXT NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
                depends_on    TEXT NOT NULL,
                version_range TEXT NOT NULL,
                optional      INTEGER NOT NULL DEFAULT 0 CHECK (optional IN (0, 1)),
                PRIMARY KEY (plugin_id, depends_on)
            )",
            // The audit trail. A ring in memory, but the durable part is what makes the interface's "recent
            // activity" survive a restart.
            "CREATE TABLE plugin_audit (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id  TEXT NOT NULL,
                capability TEXT NOT NULL,
                outcome    TEXT NOT NULL,
                at_ms      INTEGER NOT NULL,
                elapsed_ms INTEGER
            )",
            "CREATE INDEX plugin_audit_by_plugin ON plugin_audit (plugin_id, at_ms DESC)",
            // Cross-device plugin state, so a plugin mirrored on two devices can reconcile.
            "CREATE TABLE sync_records (
                plugin_id    TEXT NOT NULL,
                peer_device  TEXT NOT NULL,
                version      TEXT NOT NULL,
                digest       TEXT NOT NULL,
                synced_at_ms INTEGER NOT NULL,
                PRIMARY KEY (plugin_id, peer_device)
            )",
        ],
    },
    Migration {
        version: 3,
        name: "transfers",
        statements: &[
            // Transfer sessions, which are what make resumption possible: the receiver's bitmap is the thing
            // that is worth more than the bytes already sent.
            "CREATE TABLE transfer_sessions (
                transfer_id     TEXT PRIMARY KEY,
                peer_device     TEXT NOT NULL,
                direction       TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
                kind            TEXT NOT NULL,
                byte_length     INTEGER NOT NULL,
                chunk_size      INTEGER NOT NULL,
                digest          TEXT NOT NULL,
                received        BLOB,
                total_blocks    INTEGER NOT NULL DEFAULT 0,
                state           TEXT NOT NULL,
                created_ms      INTEGER NOT NULL,
                updated_ms      INTEGER NOT NULL,
                local_path      TEXT
            )",
            // Sessions are kept for a while and then swept. The index is what makes the sweep cheap rather than
            // a full scan on a database that may hold thousands.
            "CREATE INDEX transfer_sessions_by_age ON transfer_sessions (updated_ms)",
        ],
    },
    Migration {
        version: 4,
        name: "intents",
        statements: &[
            // Intents, persisted only when they might be replayed: an offline queue entry, or an action whose
            // result is still expected.
            "CREATE TABLE intents (
                intent_id    TEXT PRIMARY KEY,
                origin       TEXT NOT NULL,
                plugin_id    TEXT NOT NULL,
                action       TEXT NOT NULL,
                args         TEXT NOT NULL,
                state        TEXT NOT NULL,
                created_ms   INTEGER NOT NULL,
                updated_ms   INTEGER NOT NULL,
                expires_ms   INTEGER
            )",
            "CREATE INDEX intents_by_state ON intents (state, updated_ms)",
        ],
    },
    Migration {
        version: 5,
        name: "indexes",
        statements: &[
            // Added once the queries existed rather than up front, which is the honest order: an index added
            // before its query is a guess, and a migration that only adds indexes is safe to append.
            "CREATE INDEX devices_seen_by_recency ON devices_seen (last_seen_ms DESC)",
            "CREATE INDEX plugin_versions_active ON plugin_versions (plugin_id) WHERE active = 1",
            "CREATE INDEX plugin_audit_by_age ON plugin_audit (at_ms)",
        ],
    },
];

/// The schema version this build expects.
///
/// The last migration's version, computed rather than written down: a literal would be one more place to forget
/// when a step is appended.
#[must_use]
pub fn latest_version() -> u32 {
    MIGRATIONS.last().map_or(0, |migration| migration.version)
}

/// The pragmas that must be in force.
///
/// A list rather than a sequence of calls, so a caller can apply them through whichever binding it uses and a
/// test can assert the set without a database. The comments give the reason, because a pragma whose reason is
/// not written down is one somebody removes as redundant.
pub const PRAGMAS: &[(&str, &str)] = &[
    // Write-ahead logging: readers do not block the writer, which matters because the interface reads the
    // audit and metrics tables while the kernel writes them.
    ("journal_mode", "WAL"),
    // Safe with WAL, and much faster than FULL. The risk FULL removes is losing the last transactions on a
    // power cut, and WAL's own recovery covers that.
    ("synchronous", "NORMAL"),
    // Off by default in SQLite, and the kernel's schema relies on cascades: without this, deleting a plugin
    // leaves its versions, grants and dependencies behind forever.
    ("foreign_keys", "ON"),
    // Five seconds, so a brief lock from another connection waits rather than failing the operation. A longer
    // wait would make the interface appear hung; a shorter one would surface as spurious errors.
    ("busy_timeout", "5000"),
    // Temporary tables in memory, because they are used for sorting a query's results and a disk round trip for
    // something that fits in memory is pure cost.
    ("temp_store", "MEMORY"),
    // 256 MiB of memory-mapped reads: the database is small, and mapping it removes a copy from every read.
    ("mmap_size", "268435456"),
];

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

/// The statements that create the migration-version table.
///
/// Created before anything else, because the first migration needs somewhere to record that it ran. The name
/// matches what `rusqlite_migration` uses, so the two can be swapped without a data migration.
pub const VERSION_TABLE: &str = "CREATE TABLE IF NOT EXISTS __rusqlite_migration (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL
)";

/// How healthy the database is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Health {
    /// The integrity check passed.
    Sound,
    /// The check found a problem.
    ///
    /// The design document's recovery path: restore from a backup, or rebuild and tell the user what was lost.
    /// This module reports; deciding is the caller's, because only the caller knows whether a backup exists.
    Corrupt {
        /// What the engine reported.
        detail: String,
    },
    /// The check could not run.
    Unknown {
        /// Why not.
        detail: String,
    },
}

impl Health {
    /// Whether the database can be used.
    #[must_use]
    pub const fn is_sound(&self) -> bool {
        matches!(self, Self::Sound)
    }

    /// Whether the user has to be told something was lost.
    #[must_use]
    pub const fn needs_user_attention(&self) -> bool {
        matches!(self, Self::Corrupt { .. })
    }

    /// A sentence for the interface or a diagnostic bundle.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            Self::Sound => "the database passed its integrity check".to_owned(),
            Self::Corrupt { detail } => format!(
                "the database is damaged and has to be restored from a backup: {detail}"
            ),
            Self::Unknown { detail } => {
                format!("the database's integrity could not be checked: {detail}")
            }
        }
    }
}

/// Interprets the result of an integrity check.
///
/// `rusqlite` returns rows of text, the first of which is `ok` for a sound database. Anything else is a problem
/// the engine described.
#[must_use]
pub fn interpret_integrity(rows: &[String]) -> Health {
    match rows.first().map(String::as_str) {
        Some("ok") => Health::Sound,
        Some(other) => Health::Corrupt { detail: other.to_owned() },
        None => Health::Unknown {
            detail: "the check returned no rows".to_owned(),
        },
    }
}

/// The tables this build's schema defines.
///
/// A list rather than a query, so a test can assert that every table the design document names is created by
/// some migration. A table named in the document and missing from the schema is a feature that fails at its
/// first use.
pub const TABLES: &[&str] = &[
    "identity",
    "paired_devices",
    "devices_seen",
    "plugins",
    "plugin_versions",
    "plugin_grants",
    "plugin_actions",
    "plugin_deps",
    "plugin_audit",
    "sync_records",
    "transfer_sessions",
    "intents",
    "config",
];

impl fmt::Display for MigrationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_migration_list_is_a_sequence_from_one() {
        // A gap would mean a version whose shape nobody defined, and an engine applying steps in order would
        // silently skip from one shape to a different one.
        assert_eq!(check_migration_list(MIGRATIONS), Ok(()));
        assert_eq!(latest_version(), 5);
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
        assert_eq!(pending, vec![3, 4, 5]);
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

    #[test]
    fn applying_to_an_empty_database_runs_every_step() {
        let mut executed: Vec<String> = Vec::new();
        let outcome = apply(None, &mut |statement| {
            executed.push(statement.to_owned());
            Ok(())
        })
        .expect("applies");

        assert_eq!(outcome.applied, vec![1, 2, 3, 4, 5]);
        assert_eq!(outcome.version, latest_version());
        assert!(outcome.changed_anything());
        assert!(outcome.describe().contains("5 migration"));

        let total: usize = MIGRATIONS.iter().map(|migration| migration.statements.len()).sum();
        assert_eq!(executed.len(), total, "every statement ran exactly once");
    }

    #[test]
    fn applying_to_a_current_database_runs_nothing() {
        let mut executed = 0usize;
        let outcome = apply(Some(latest_version()), &mut |_| {
            executed += 1;
            Ok(())
        })
        .expect("applies");

        assert_eq!(executed, 0);
        assert!(!outcome.changed_anything());
        assert!(outcome.describe().contains("already at version"));
    }

    #[test]
    fn applying_resumes_from_the_recorded_version() {
        // A half-finished migration must not be repeated: the first step may have created tables, and running it
        // again would fail on the second device that resumed.
        let mut versions: Vec<String> = Vec::new();
        let outcome = apply(Some(2), &mut |statement| {
            versions.push(statement.to_owned());
            Ok(())
        })
        .expect("applies");

        assert_eq!(outcome.applied, vec![3, 4, 5]);
        // And none of the earlier steps' statements appear.
        let earlier: Vec<String> = MIGRATIONS[..2]
            .iter()
            .flat_map(|migration| migration.statements.iter())
            .map(|statement| (*statement).to_owned())
            .collect();
        for statement in earlier {
            assert!(!versions.contains(&statement), "an applied step ran again");
        }
    }

    #[test]
    fn a_failed_statement_names_the_migration_and_the_statement() {
        // The log line is what somebody has to act on, so it has to say which step and which statement rather
        // than just that migration failed.
        let mut count = 0usize;
        let result = apply(None, &mut |_| {
            count += 1;
            if count == 3 { Err("table already exists".to_owned()) } else { Ok(()) }
        });

        match result {
            Err(SchemaError::StatementFailed { version, name, index, detail }) => {
                assert_eq!(version, 1, "the third statement is in the first migration");
                assert_eq!(name, "init");
                assert_eq!(index, 2);
                assert!(detail.contains("already exists"));
            }
            other => panic!("expected a statement failure, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_migration_reports_the_versions_that_succeeded() {
        // The recorded version is left at the last step that completed, so the next run resumes rather than
        // repeating work — which means the caller has to be told where it got to.
        let mut count = 0usize;
        let result = apply(Some(1), &mut |_| {
            count += 1;
            // The second migration's first statement fails.
            if count == 1 { Err("nope".to_owned()) } else { Ok(()) }
        });

        match result {
            Err(SchemaError::StatementFailed { version, .. }) => assert_eq!(version, 2),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn applying_to_a_newer_database_is_refused_before_running_anything() {
        let mut executed = 0usize;
        let result = apply(Some(latest_version() + 5), &mut |_| {
            executed += 1;
            Ok(())
        });

        assert!(matches!(result, Err(SchemaError::TooNew { .. })));
        assert_eq!(executed, 0, "nothing may run against a schema this build cannot understand");
    }

    #[test]
    fn an_integrity_check_that_passes_is_sound() {
        assert_eq!(interpret_integrity(&["ok".to_owned()]), Health::Sound);
        assert!(Health::Sound.is_sound());
        assert!(!Health::Sound.needs_user_attention());
        assert!(Health::Sound.explain().contains("passed"));
    }

    #[test]
    fn an_integrity_check_that_finds_a_problem_is_reported() {
        let health = interpret_integrity(&["row 5 missing from index".to_owned()]);
        match &health {
            Health::Corrupt { detail } => assert!(detail.contains("missing from index")),
            other => panic!("expected damage, got {other:?}"),
        }
        assert!(!health.is_sound());
        assert!(health.needs_user_attention());
        // The sentence has to tell the user what happens next, not only that something broke.
        assert!(health.explain().contains("backup"));
    }

    #[test]
    fn an_integrity_check_that_cannot_run_is_not_a_failure() {
        // Not being able to tell is a different claim from the database being damaged, and telling a user their
        // data is corrupt when it is not is the worse mistake.
        let health = interpret_integrity(&[]);
        assert!(matches!(health, Health::Unknown { .. }));
        assert!(!health.is_sound());
        assert!(!health.needs_user_attention());
    }

    #[test]
    fn the_version_table_statement_is_idempotent() {
        // It runs before the first migration, and on a resumed database it runs again.
        assert!(VERSION_TABLE.contains("IF NOT EXISTS"));
    }

    #[test]
    fn a_migration_outcome_displays_its_summary() {
        let outcome = MigrationOutcome { applied: vec![1, 2], version: 2 };
        assert_eq!(outcome.to_string(), outcome.describe());
        assert!(outcome.describe().contains('2'));
    }

    #[test]
    fn schema_errors_explain_themselves() {
        let errors = vec![
            SchemaError::TooNew { found: 9, known: 5 },
            SchemaError::MalformedList("x"),
            SchemaError::StatementFailed {
                version: 1,
                name: "init",
                index: 0,
                detail: "x".to_owned(),
            },
            SchemaError::Corrupt("x".to_owned()),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn the_too_new_message_names_both_versions() {
        // The message is what a user sees, and "the database is too new" without the numbers gives them nothing
        // to act on.
        let text = SchemaError::TooNew { found: 9, known: 5 }.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('5'), "{text}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Whatever version is recorded, the result is either a usable state with the right pending steps or a
        /// refusal. No version produces a state that claims to be usable and lists steps backwards.
        #[test]
        fn a_recorded_version_always_yields_a_coherent_state(recorded in proptest::option::of(0u32..20)) {
            let state = schema_state(recorded);
            match state {
                SchemaState::Empty => {
                    prop_assert!(state.is_usable());
                    prop_assert_eq!(state.pending().len(), MIGRATIONS.len());
                }
                SchemaState::At { version } => {
                    prop_assert!(state.is_usable());
                    prop_assert!(version <= latest_version());
                    // Every pending step is above the recorded version, and the set is contiguous up to the
                    // latest — a gap would mean a shape nobody defined.
                    let pending: Vec<u32> = state.pending().iter().map(|m| m.version).collect();
                    let expected: Vec<u32> = ((version + 1)..=latest_version()).collect();
                    prop_assert_eq!(pending, expected);
                }
                SchemaState::Newer { found, known } => {
                    prop_assert!(!state.is_usable());
                    prop_assert!(found > known);
                    prop_assert!(state.pending().is_empty());
                }
            }
        }

        /// Applying is idempotent in the sense that matters: running it twice from the version it reached runs
        /// nothing the second time. A migration that ran twice would fail on the second device that resumed.
        #[test]
        fn applying_twice_runs_nothing_the_second_time(from in 0u32..=5) {
            let first = apply(Some(from), &mut |_| Ok(())).expect("applies");
            let mut second_count = 0usize;
            let second = apply(Some(first.version), &mut |_| {
                second_count += 1;
                Ok(())
            })
            .expect("applies");

            prop_assert_eq!(second_count, 0);
            prop_assert!(!second.changed_anything());
            prop_assert_eq!(second.version, latest_version());
        }

        /// The statement count an application runs matches the steps it reports, so the outcome cannot claim to
        /// have applied a migration whose statements never ran.
        #[test]
        fn the_reported_versions_match_the_statements_that_ran(from in 0u32..=5) {
            let mut count = 0usize;
            let outcome = apply(Some(from), &mut |_| {
                count += 1;
                Ok(())
            })
            .expect("applies");

            let expected: usize = outcome
                .applied
                .iter()
                .filter_map(|version| MIGRATIONS.iter().find(|m| m.version == *version))
                .map(|migration| migration.statements.len())
                .sum();
            prop_assert_eq!(count, expected);
        }
    }
}
