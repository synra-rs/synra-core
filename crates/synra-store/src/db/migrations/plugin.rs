//! Plugin storage and synchronization migrations.

use super::Migration;
pub(crate) const V8: Migration = Migration {
        version: 8,
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
    };

pub(crate) const V9: Migration = Migration {
        version: 9,
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
    };

pub(crate) const V10: Migration = Migration {
        version: 10,
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
    };

pub(crate) const V11: Migration = Migration {
        version: 11,
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
    };

pub(crate) const V12: Migration = Migration {
        version: 12,
        name: "audit-trace",
        statements: &[
            // ★ The audit trail's `trace_id` was in the DTO from the first version and in no row: the session that makes a
            // call did not know the action's trace, so the interface's "which action was this?" had no answer after a
            // restart. The column is nullable rather than backfilled: rows written by an older build have no trace to
            // recover, and a NOT NULL column would refuse to add itself to a table that already has them.
            "ALTER TABLE plugin_audit ADD COLUMN trace_id TEXT",
        ],
    };

pub(crate) const V13: Migration = Migration {
        version: 13,
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
    };












