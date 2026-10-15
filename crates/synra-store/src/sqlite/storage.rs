//! What a plugin keeps between runs.
//!
//! # What this is for
//!
//! A plugin that wants to remember anything — a server it talks to, which of its notifications are muted, where the user
//! was last time — has nowhere else to put it. The WIT interface declares `storage-get`/`set`/`delete`/`keys`/`quota`,
//! the capability catalogue has `storage:local:read` and `storage:local:write`, and **every host in this repository
//! answered all five with `notImplemented`** until this table existed. So a plugin's only way to persist a setting was to
//! ask the user for it again on every run.
//!
//! # Why the kernel does not look inside a value
//!
//! Because it is the plugin's. The value is whatever it serialised — JSON, a string, a version number — and a kernel that
//! parsed it would be one that had to change whenever the plugin's private format did. The only thing enforced here is
//! **size**, and that is enforced by the host against the plugin's quota rather than by this layer, which does not know
//! what the quota is.
//!
//! # Why a key space per plugin
//!
//! Because the primary key is the pair. Two plugins that both want a key called `settings` are two plugins with two
//! settings, and a shared key space would make installing an unrelated plugin able to change what another one reads.

use rusqlite::{OptionalExtension, params};

use super::{DbError, SynraDb};

impl SynraDb {
    /// Reads a value a plugin stored.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn storage_get(&self, plugin_id: &str, key: &str) -> Result<Option<String>, DbError> {
        self.connection
            .query_row(
                "SELECT value FROM plugin_storage WHERE plugin_id = ?1 AND key = ?2",
                params![plugin_id, key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }

    /// Writes a value, replacing whatever was under that key.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn storage_set(&self, plugin_id: &str, key: &str, value: &str, now_ms: i64) -> Result<(), DbError> {
        // An upsert rather than an insert-then-update: two statements would be two chances for the second to fail and
        // leave the first applied, and a `set` that half happened is a value nobody chose.
        self.connection
            .execute(
                "INSERT INTO plugin_storage (plugin_id, key, value, updated_ms) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(plugin_id, key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms",
                params![plugin_id, key, value, now_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Removes a value, reporting whether there was one.
    ///
    /// # Returns
    ///
    /// `false` when the key was not there — which is not an error, because a plugin deleting something twice has not made
    /// a mistake, but it is worth reporting so a caller can tell "it is gone" from "it was never here".
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn storage_delete(&self, plugin_id: &str, key: &str) -> Result<bool, DbError> {
        let removed = self
            .connection
            .execute(
                "DELETE FROM plugin_storage WHERE plugin_id = ?1 AND key = ?2",
                params![plugin_id, key],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(removed > 0)
    }

    /// The keys a plugin has, ordered, optionally restricted to a prefix.
    ///
    /// Ordered because this is what an interface lists, and an order that changed between reads would make a list move
    /// while a user was reading it.
    ///
    /// # Why the prefix is escaped rather than concatenated
    ///
    /// Because `LIKE` reads `%` and `_` in the pattern as wildcards, and a plugin whose keys contain either would get
    /// back keys it did not ask for. A prefix is a prefix, not a pattern — the caller is naming characters, not a shape.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn storage_keys(&self, plugin_id: &str, prefix: Option<&str>) -> Result<Vec<String>, DbError> {
        // ★ One statement with a null-means-no-filter, rather than two prepared queries.
        //
        // Two queries in a `match` cannot share a `query_map` — the closure and the parameter list are different types —
        // so the alternative was duplicating the prepare, the map and the collect. This says the same thing once: when the
        // pattern is absent the `LIKE` is not consulted, and when it is present it is consulted with the escaping above.
        let pattern = prefix.map(escape_like);

        let mut statement = self
            .connection
            .prepare(
                "SELECT key FROM plugin_storage
                 WHERE plugin_id = ?1 AND (?2 IS NULL OR key LIKE ?2 ESCAPE '\\')
                 ORDER BY key",
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map(params![plugin_id, pattern], |row| row.get::<_, String>(0))
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.collect::<Result<Vec<String>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }

    /// How many bytes a plugin's storage is using.
    ///
    /// # What is counted, and why it is not the file's size
    ///
    /// `length(value)` in bytes — the values alone. A quota is a limit on what a plugin *keeps*, and counting the keys,
    /// the row overhead or the page size would make the number depend on SQLite's storage layout, which changes between
    /// versions and would make a plugin fail its quota after an upgrade to this build for reasons it cannot see.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn storage_used_bytes(&self, plugin_id: &str) -> Result<u64, DbError> {
        self.connection
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(CAST(value AS BLOB))), 0) FROM plugin_storage WHERE plugin_id = ?1",
                params![plugin_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|used| u64::try_from(used).unwrap_or(0))
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }

    /// Removes everything a plugin stored.
    ///
    /// # Returns
    ///
    /// How many keys were removed.
    ///
    /// # Why this exists when the table cascades
    ///
    /// Because the cascade only fires when the plugin's *row* goes, and an uninstall may keep the row — a reinstall that
    /// remembers nothing is what a user expects from "remove", while a row kept for the audit trail is what the design
    /// asks for. This is how the two are told apart, and it is the caller's decision which happens.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn storage_clear(&self, plugin_id: &str) -> Result<usize, DbError> {
        self.connection
            .execute("DELETE FROM plugin_storage WHERE plugin_id = ?1", params![plugin_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }
}

/// Escapes a prefix for `LIKE`, so `%` and `_` in it mean themselves.
///
/// The backslash is the escape character in the pattern above, and it is itself escaped so a prefix ending in one does not
/// swallow the `%` that follows it.
#[must_use]
fn escape_like(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len() + 1);
    for character in prefix.chars() {
        if matches!(character, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped.push('%');
    escaped
}

#[cfg(test)]
mod tests;
