//! One schema step, the list of them, and the pragmas they assume.
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
    Migration {
        version: 6,
        name: "pairing-tokens",
        statements: &[
            // The secret a paired peer presents on the next link, so a handshake can answer "is this the device I paired
            // with" rather than "someone is dialling". It is 32 bytes, stored as lowercase hex because that is how it
            // travels on the wire, and nullable because a row written before this migration has no token: such a device
            // is paired but must pair again, which the handshake reports as `Stale` rather than as a refusal.
            "ALTER TABLE paired_devices ADD COLUMN link_token TEXT",
        ],
    },
    Migration {
        version: 7,
        name: "paired-address",
        statements: &[
            // Where a paired device was last reached, as `host:port`. Recorded because it is the one fact about a peer
            // this side *observed* rather than was told: the name is whatever the peer chose to call itself, and a user
            // deciding about a prompt has nothing else to recognise a machine by. Nullable because a row written before
            // this migration, or a pairing accepted with no socket under it — a local test — has no address, and an
            // empty string is a value a later query would have to special-case.
            "ALTER TABLE paired_devices ADD COLUMN last_address TEXT",
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
