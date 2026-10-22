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
/// Split by area rather than by table so that a step is one coherent change: an interrupted migration then leaves the
/// database at a version whose shape is somebody reasoned about, rather than halfway through adding a column.
///
/// ★ It used to say how many steps there were — "five" — and that number was wrong for four steps by the time anybody
/// looked. A count in a doc comment is a number that can only be maintained by remembering, so it is not here.
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
    Migration {
        version: 8,
        name: "plugin-storage",
        statements: &[
            // ★ What a plugin keeps between runs, which until now was nothing at all.
            //
            // The WIT interface has declared `storage-get`/`set`/`delete`/`keys`/`quota` since it was written, the
            // capability catalogue has `storage:local:read` and `storage:local:write`, and every host in the repository
            // answered all five with `notImplemented` — so a plugin that wanted to remember a setting had to ask the user
            // for it again on every run. This is the table that makes the capability mean something.
            //
            // The primary key is the pair, so a plugin's key space is its own and a `set` is an upsert. Nothing about the
            // *value* is constrained: it is whatever the plugin serialised, because the kernel has no business parsing
            // it — and a kernel that validated a plugin's private format would be one that had to change when the plugin
            // did.
            //
            // `ON DELETE CASCADE` on the plugin row, so removing a plugin removes what it stored. The alternative is a
            // table that grows for ever with the leavings of things nobody has installed, and no query that could
            // attribute them to anything once the row above is gone.
            "CREATE TABLE plugin_storage (
                plugin_id    TEXT NOT NULL REFERENCES plugins(plugin_id) ON DELETE CASCADE,
                key          TEXT NOT NULL,
                value        TEXT NOT NULL,
                updated_ms   INTEGER NOT NULL,
                PRIMARY KEY (plugin_id, key)
            )",
            // Listing a plugin's keys is the one read that is not by primary key, and it is on a path a settings screen
            // takes. Without this it is a scan of every plugin's storage to find one plugin's.
            "CREATE INDEX plugin_storage_by_key ON plugin_storage(plugin_id, key)",
        ],
    },
    Migration {
        version: 9,
        name: "intent-documents",
        statements: &[
            // ★ The `intents` table could not hold an intent, and this is why it is rebuilt rather than added to.
            //
            // It was created by the first migration and then never read or written by any code in either workspace. Its
            // columns were a projection of an intent designed before the type existed, and none of them could carry what an
            // intent actually has: the trace, the `Choice`, the candidate list, the admission refusal, or the request id a
            // dispatch was sent under. A restored intent built from those columns would have forgotten which plugin was
            // going to answer it — which is worse than not persisting at all, because it would look like it had worked.
            //
            // So the document is the row now. `document` holds the kernel's own serialisation of the whole intent, and the
            // columns beside it are the projection that the two queries the store must make **without parsing every row**:
            // the retention sweep, which filters by state, and the idempotency lookup, which is by request.
            //
            // ★ Dropping the old table loses nothing, and that is a fact rather than a hope: no production code path ever
            // read or wrote it. The rule that a published migration is never edited is not being bent here either — this is
            // a new step, and the one it replaces is still in the list, still applied, still tested.
            "DROP TABLE intents",
            "CREATE TABLE intents (
                intent_id     TEXT PRIMARY KEY,
                state         TEXT NOT NULL,
                created_ms    INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                origin_device TEXT,
                request_id    TEXT,
                document      TEXT NOT NULL
            )",
            // The retention rule is "finished, and older than N" — both halves are in the index, in the order the query
            // filters them.
            "CREATE INDEX intents_by_state ON intents (state, updated_ms)",
            // ★ UNIQUE, and deliberately: `Board::raise` refuses a repeated request *in memory*, and the whole point of
            // persisting is that a restart must not lose that. The kernel mints a fresh intent id for every raise, so the
            // primary key cannot catch a repeat — this index is what turns "the same request is never two intents" from a
            // rule the board remembers into one the database enforces. A row that violates it is a bug in the caller, and
            // the honest answer to a bug is an error rather than a second copy of a user's action.
            //
            // NULLs are distinct in a SQLite unique index, so the many intents raised locally — with no origin device and
            // no request — do not collide.
            "CREATE UNIQUE INDEX intents_by_request ON intents (origin_device, request_id)",
        ],
    },
    Migration {
        version: 10,
        name: "sync-log",
        statements: &[
            // ★ The record is the row, which is the shape v9 established for `intents` — and for the same reason.
            //
            // `sync_records` is one row per `(plugin_id, peer_device)`: what a peer holds **now**, replaced on every round.
            // That is the state the third step of the sync flow needs. It is not a history: a round that failed, a round
            // that was skipped because both ends already agreed, what it cost in bytes — none of that survives in a table
            // with one row per peer. `16` §5.5 asks for a record per sync and `SyncRecord` grew the fields for it in round
            // 133, with nowhere to put them.
            //
            // So `document` holds the record as the kernel serialises it, and the columns beside it are the projection a
            // history query needs **without parsing every row**: newest first, filtered by plugin.
            "CREATE TABLE sync_log (
                sync_id        TEXT PRIMARY KEY,
                plugin_id      TEXT NOT NULL,
                peer_device    TEXT NOT NULL,
                started_at_ms  INTEGER NOT NULL,
                finished_at_ms INTEGER,
                document       TEXT NOT NULL
            )",
            "CREATE INDEX sync_log_by_plugin ON sync_log (plugin_id, started_at_ms)",
        ],
    },
    Migration {
        version: 11,
        name: "clipboard-capability",
        statements: &[
            // ★ One permission, one name. The gate has always required `platform:read-clipboard` /
            // `platform:write-clipboard`; the capability documentation used `platform:clipboard:read` /
            // `platform:clipboard:write`, so a manifest written from it produced grant rows the gate never consulted.
            // The manifest reader now canonicalises new declarations; this step repairs the rows already on disk.
            //
            // The DELETE-then-UPDATE pair handles a plugin that managed to record both spellings: the primary key is
            // `(plugin_id, capability)`, so a plain UPDATE would fail on the collision, and `UPDATE OR REPLACE` would
            // silently drop the canonical row's own decision. Keeping the canonical row and removing the legacy one is
            // the only outcome that does not lose a decision the user can still see.
            "DELETE FROM plugin_grants WHERE capability = 'platform:clipboard:read' AND EXISTS (
                 SELECT 1 FROM plugin_grants AS canonical
                 WHERE canonical.plugin_id = plugin_grants.plugin_id
                   AND canonical.capability = 'platform:read-clipboard'
             )",
            "UPDATE plugin_grants SET capability = 'platform:read-clipboard'
             WHERE capability = 'platform:clipboard:read'",
            "DELETE FROM plugin_grants WHERE capability = 'platform:clipboard:write' AND EXISTS (
                 SELECT 1 FROM plugin_grants AS canonical
                 WHERE canonical.plugin_id = plugin_grants.plugin_id
                   AND canonical.capability = 'platform:write-clipboard'
             )",
            "UPDATE plugin_grants SET capability = 'platform:write-clipboard'
             WHERE capability = 'platform:clipboard:write'",
        ],
    },
    Migration {
        version: 12,
        name: "publisher-trust",
        statements: &[
            // What this device knows about the keys that sign packages. `trust` is one of `seen`, `trusted`, `revoked`:
            // a signature is checked on every install, and this table is what turns "a key I have met" into "a key the
            // user chose". `pubkey` is kept because a fingerprint cannot be turned back into a key.
            "CREATE TABLE publishers (
                publisher_id  TEXT PRIMARY KEY,
                fingerprint   TEXT NOT NULL,
                pubkey        TEXT NOT NULL,
                trust         TEXT NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                decided_ms    INTEGER
            )",
            "CREATE INDEX publishers_by_fingerprint ON publishers (fingerprint)",
        ],
    },
    Migration {
        version: 13,
        name: "audit-trace",
        statements: &[
            // ★ The audit trail's `trace_id` was in the DTO from the first version and in no row: the session that makes a
            // call did not know the action's trace, so the interface's "which action was this?" had no answer after a
            // restart. The column is nullable rather than backfilled: rows written by an older build have no trace to
            // recover, and a NOT NULL column would refuse to add itself to a table that already has them.
            "ALTER TABLE plugin_audit ADD COLUMN trace_id TEXT",
        ],
    },
    Migration {
        version: 14,
        name: "intent-retries",
        statements: &[
            // ★ The retry schedule was in memory, so every restart started the backoff from zero. A dispatch that had
            // already been retried five times began again at thirty seconds, and a device asleep across several launches
            // was retried as if for the first time each time. One row per intent, keyed by the intent itself: a retry that
            // outlives its intent is a schedule for work that does not exist.
            //
            // `next_at_ms` is nullable because a given-up entry has no next time; `gave_up` says so explicitly rather than
            // making a reader infer it from NULL. The cascade is why this table does not need its own sweep: deleting an
            // intent removes its schedule, and `foreign_keys` is on for every connection.
            "CREATE TABLE intent_retries (
                intent_id   TEXT PRIMARY KEY REFERENCES intents(intent_id) ON DELETE CASCADE,
                attempts    INTEGER NOT NULL,
                next_at_ms  INTEGER,
                gave_up     INTEGER NOT NULL DEFAULT 0
            )",
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
