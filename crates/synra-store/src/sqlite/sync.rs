use rusqlite::params;

use crate::records::{RowError, SyncRow, columns};

use super::{DbError, SynraDb};

impl SynraDb {
    /// What every device holds, ordered so two reads agree.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::plugins`].
    pub fn sync_records(&self) -> Result<Vec<SyncRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM sync_records ORDER BY plugin_id, peer_device",
            columns::SYNC.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(SyncRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<String>>(3)?.as_deref(),
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            // The same shape as `plugins.rs`, and for the same reason: the closure cannot answer a `RowError`, so it
            // answers `Result<Result<SyncRow, RowError>, rusqlite::Error>` — outer first, then inner.
            .collect::<Result<Vec<Result<SyncRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        rows.into_iter().collect::<Result<Vec<SyncRow>, RowError>>().map_err(DbError::from)
    }

    /// Records what a peer holds for a plugin, replacing what was known.
    ///
    /// ★ **It replaces rather than appends**, because the table's primary key is `(plugin_id, peer_device)` and that is
    /// the right shape: this answers "does the peer already have it", and two rows for one peer would make that question
    /// have two answers. The history of rounds is [`crate::plugin_sync::SyncRecord`]'s job.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write fails.
    pub fn record_sync(
        &self,
        plugin_id: &str,
        peer_device: &str,
        version: &str,
        digest: &str,
        synced_at_ms: i64,
    ) -> Result<(), DbError> {
        self.connection
            .execute(
                "INSERT INTO sync_records (plugin_id, peer_device, version, digest, synced_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(plugin_id, peer_device) DO UPDATE SET \
                     version = excluded.version, \
                     digest = excluded.digest, \
                     synced_at_ms = excluded.synced_at_ms",
                params![plugin_id, peer_device, version, digest, synced_at_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Replaces everything known about one peer with what it just said it holds.
    ///
    /// # Why a replacement and not a series of upserts
    ///
    /// Because a live answer is **complete**: it is the whole list, not a delta. A plugin the peer has uninstalled is
    /// absent from the answer, and an upsert has no way to notice an absence — its old row would stay for ever, and every
    /// plan would keep claiming the peer holds something it does not.
    ///
    /// # Why one transaction
    ///
    /// Because the delete is only meaningful together with the insert that follows it. A failure between them would leave
    /// the peer with **no** rows, which reads as "it has nothing" — the direction that wastes a transfer, but worse, the
    /// answer this device gave was one it could not support. A rolled-back delete restores exactly what was known.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the delete or an insert is refused. Nothing changed: the transaction is dropped
    /// unfinished.
    pub fn replace_sync_for_peer(
        &self,
        peer_device: &str,
        held: &[(String, String, String)],
        synced_at_ms: i64,
    ) -> Result<(), DbError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        transaction
            .execute("DELETE FROM sync_records WHERE peer_device = ?1", params![peer_device])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        for (plugin_id, version, digest) in held {
            transaction
                .execute(
                    "INSERT INTO sync_records (plugin_id, peer_device, version, digest, synced_at_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![plugin_id, peer_device, version, digest, synced_at_ms],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
        }
        transaction
            .commit()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }
}
