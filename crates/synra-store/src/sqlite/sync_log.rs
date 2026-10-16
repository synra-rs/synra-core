use rusqlite::params;

use crate::records::{RowError, SyncLogRow, columns};

use super::{DbError, SynraDb};

impl SynraDb {
    /// The most recent rounds, newest first, or those of one plugin.
    ///
    /// # Why the plugin filter is a column and the rest is a document
    ///
    /// Because these are the two questions the history screen asks, and both can be answered from the projection —
    /// a query that had to parse every `document` to find a plugin's rounds would get slower with every sync ever made.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::plugins`].
    pub fn sync_log(&self, plugin_id: Option<&str>, limit: u32) -> Result<Vec<SyncLogRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM sync_log WHERE (?1 IS NULL OR plugin_id = ?1) \
             ORDER BY started_at_ms DESC LIMIT ?2",
            columns::SYNC_LOG.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map(params![plugin_id, limit], |row| {
                Ok(SyncLogRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?.as_deref(),
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<SyncLogRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        rows.into_iter().collect::<Result<Vec<SyncLogRow>, RowError>>().map_err(DbError::from)
    }

    /// Records a round, replacing any earlier row with the same identifier.
    ///
    /// ★ **Replacing is right here too**, even though this is a log: a round is written twice — once when it starts and
    /// once when it ends — and the second write is the same round, not a second one. Two rows for one `sync_id` would
    /// make the history show a round twice, once of them claiming it never finished.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write fails.
    pub fn record_sync_log(&self, row: &SyncLogRow) -> Result<(), DbError> {
        self.connection
            .execute(
                "INSERT INTO sync_log (sync_id, plugin_id, peer_device, started_at_ms, finished_at_ms, document) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(sync_id) DO UPDATE SET \
                     plugin_id = excluded.plugin_id, \
                     peer_device = excluded.peer_device, \
                     started_at_ms = excluded.started_at_ms, \
                     finished_at_ms = excluded.finished_at_ms, \
                     document = excluded.document",
                params![
                    row.sync_id,
                    row.plugin_id,
                    row.peer_device,
                    row.started_at_ms,
                    row.finished_at_ms,
                    row.document
                ],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }
}
