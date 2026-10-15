//! The durable half of the audit trail.
//!
//! # Why this table existed and was empty
//!
//! The first migration created `plugin_audit` and its own comment says what it is for: *"A ring in memory, but the durable
//! part is what makes the interface's 'recent activity' survive a restart."* The ring was written
//! ([`PluginSet`](synra_core) drains a plugin's buffered entries into it after every call) and nothing ever wrote the
//! table — so the audit a user sees is the last ten thousand calls **of this process**, and a restart empties it.
//!
//! # What the store knows, and what it does not
//!
//! It is given the four things a row holds, as plain values: which plugin, which capability, how it ended, and when. It
//! does not know what a `Capability` is, or what the outcome names mean — those belong to the crates that define them, and
//! a store that parsed them would need a migration every time one was renamed.
//!
//! # And what is deliberately not here
//!
//! Any *content*. The design's audit has no field for what a call carried, and that absence is the reason the record is
//! safe to keep longer than a log: a capability describes **destinations**, never contents.

use rusqlite::params;

use crate::records::{AuditRecord, RowError, columns};

use super::{DbError, SynraDb};

impl SynraDb {
    /// Writes one gated call.
    ///
    /// # Why this appends rather than upserts
    ///
    /// Because every call is its own event. There is no identity to update: two `device:list` calls a millisecond apart are
    /// two facts, and the interface's "recent activity" is a list of them. The ring above this is what is bounded; the table
    /// is the history, and the retention sweep is what keeps it from growing for ever.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn record_audit(&self, entry: &AuditRecord) -> Result<(), DbError> {
        self.connection
            .execute(
                "INSERT INTO plugin_audit (plugin_id, capability, outcome, at_ms, elapsed_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    entry.plugin_id.as_str(),
                    entry.capability.as_str(),
                    entry.outcome.as_str(),
                    entry.at_ms,
                    // Already an `i64`: the conversion from the entry's `u64` happens in the host, which is where the
                    // entry is read — a store that converted it would be a second place the two clocks meet.
                    entry.elapsed_ms,
                ],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Every recorded call, newest first so a reader sees the most recent without sorting.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`], or [`DbError::Row`] for a row the schema should not have allowed.
    pub fn audit_trail(&self) -> Result<Vec<AuditRecord>, DbError> {
        let sql = format!(
            "SELECT {} FROM plugin_audit ORDER BY at_ms DESC, id DESC",
            columns::AUDIT.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(AuditRecord::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<AuditRecord, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<AuditRecord>, RowError>>().map_err(DbError::from)
    }

    /// How many calls are recorded.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the count cannot be read.
    pub fn audit_count(&self) -> Result<usize, DbError> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM plugin_audit", [], |row| row.get(0))
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// Forgets recorded calls older than `before_ms`.
    ///
    /// # Returns
    ///
    /// How many rows were removed.
    ///
    /// # Why the retention is by age alone, unlike the intents'
    ///
    /// Because an audit record has no state that is still in progress: it is written once, when the call it is about has
    /// already ended. There is no "running" record to protect, so the rule the design gives it — a number of days — is the
    /// whole rule.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the delete is refused.
    pub fn forget_audit_before(&self, before_ms: i64) -> Result<usize, DbError> {
        self.connection
            .execute("DELETE FROM plugin_audit WHERE at_ms < ?1", params![before_ms])
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }
}

#[cfg(test)]
mod tests;
