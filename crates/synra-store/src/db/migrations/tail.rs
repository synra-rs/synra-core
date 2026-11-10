//! Later compatibility and repair migrations.

use super::Migration;
pub(crate) const V14: Migration = Migration {
        version: 14,
        name: "plugin-update-checks",
        statements: &["CREATE TABLE plugin_update_checks (
                plugin_id TEXT PRIMARY KEY REFERENCES plugins(plugin_id) ON DELETE CASCADE,
                current_version TEXT NOT NULL,
                checked_at_ms INTEGER NOT NULL,
                registry TEXT,
                available_version TEXT,
                added_capabilities TEXT NOT NULL
            )"],
    };

pub(crate) const V15: Migration = Migration {
        version: 15,
        name: "plugin-signer",
        statements: &[
            // ★ A version row knew what bytes ran and nothing about who signed them. That made "revoke this key" a scan
            // of installed manifests by publisher id — the v1 single-key assumption — and it made a safe automatic
            // update impossible to decide without downloading and installing first. The signer is a property of the
            // version, so it belongs on the version row.
            //
            // Nullable because a local package may be unsigned; that is a different fact from "signed by nobody" and
            // the installer already records it as such.
            "ALTER TABLE plugin_versions ADD COLUMN publisher_id TEXT",
            "ALTER TABLE plugin_versions ADD COLUMN fingerprint TEXT",
            "CREATE INDEX plugin_versions_by_fingerprint ON plugin_versions (fingerprint, active)",
        ],
    };

pub(crate) const V16: Migration = Migration {
        version: 16,
        name: "update-retries",
        statements: &[
            // ★ An automatic update that failed waited a whole day for the next attempt, which made a transient refusal —
            // a closed socket, a mirror that was briefly down — cost a day of being out of date. The attempt count is on
            // the check because the check is the row that already knows what is available.
            "ALTER TABLE plugin_update_checks ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE plugin_update_checks ADD COLUMN retry_at_ms INTEGER",
        ],
    };

pub(crate) const V17: Migration = Migration {
        version: 17,
        name: "forget-auto-paired",
        statements: &[
            // ★ One-time repair, and deliberately destructive. A development build answered a pairing request with
            // `accepted: true` without showing either person the six digits. Those rows are indistinguishable from a
            // real pairing after the fact, and leaving them behind makes the devices screen show a pair that nobody
            // agreed to. The app has not shipped, so forgetting every pairing once is the honest reset; remove this
            // migration before the first release rather than carrying it forever.
            "DELETE FROM paired_devices",
        ],
    };












