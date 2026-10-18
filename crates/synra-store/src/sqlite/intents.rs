//! Persisting intents, and forgetting the ones that are done with.
//!
//! # Why this module exists now
//!
//! Because the `intents` table was created by the first migration and then never read or written by any code in either
//! workspace. An intent lived in the kernel's in-memory `Board` and nothing else, so a daemon restart lost every one of
//! them — and the design's retention rule ("24 hours after they finish", `17 §6`) is a rule about **rows**, which needs
//! rows to exist. This is where they do.
//!
//! # What the store does and does not know
//!
//! `state` and `args` travel as text. The store compares `state` to a set of spellings it is *told*, and it never decides
//! that an intent is finished by itself — because "finished" is the kernel's judgement, and a store that guessed it from a
//! string would be a second place the state machine is written down.
//!
//! # Two things this must never delete
//!
//! `17 §6` names them: user data (`plugin_data/files/`, which lives in `plugin_storage`) and pinned plugin versions. A
//! collector that removed an intent has no business near either, and there is a test that says so rather than a comment.

use rusqlite::params;

use crate::records::{IntentRecord, RowError, columns};

use super::{DbError, SynraDb};

impl SynraDb {
    /// Writes an intent, or updates the one already stored under the same identifier.
    ///
    /// # Why an upsert rather than an insert
    ///
    /// Because an intent changes as it is worked on: raised, matched, decided, finished. Every one of those is the same
    /// intent, and a store that inserted a row per change would answer `load_intents` with a history rather than a state —
    /// which is what the audit trail is for and not what a board is.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn save_intent(&self, intent: &IntentRecord) -> Result<(), DbError> {
        timed_write!(self, "intent", {
            self.connection
                .execute(
                    "INSERT INTO intents \
                         (intent_id, state, created_ms, updated_ms, origin_device, request_id, document) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                     ON CONFLICT (intent_id) DO UPDATE SET \
                         state = ?2, \
                         -- ★ `created_ms` is deliberately absent: it is when the intent was raised, and a later write is
                         -- not a later raising. Overwriting it would make every intent look as though it had just started
                         -- — and the retention rule is measured from when it *finished*, so the two must not be the same
                         -- number by accident.
                         updated_ms = ?4, \
                         origin_device = ?5, \
                         request_id = ?6, \
                         document = ?7",
                    params![
                        intent.intent_id.as_str(),
                        intent.state.as_str(),
                        intent.created_ms,
                        intent.updated_ms,
                        intent.origin_device.as_deref(),
                        intent.request_id.as_deref(),
                        intent.document.as_str(),
                    ],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
    }

    /// Every stored intent, oldest first so two runs agree.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`], or [`DbError::Row`] for a row the schema should not have allowed.
    pub fn load_intents(&self) -> Result<Vec<IntentRecord>, DbError> {
        let sql = format!(
            "SELECT {} FROM intents ORDER BY created_ms, intent_id",
            columns::INTENT.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(IntentRecord::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?.as_deref(),
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<IntentRecord, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<IntentRecord>, RowError>>().map_err(DbError::from)
    }

    /// The intent raised under a peer's request, when there is one.
    ///
    /// # Why the store answers this rather than the caller filtering
    ///
    /// Because it is the idempotency lookup, and after a restart it is the *only* way to answer it: the board is rebuilt
    /// from these rows, and a peer that resends a request must be recognised from what was persisted rather than from what
    /// happens to be in memory. The unique index on the pair is what makes the answer at most one row.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`], or [`DbError::Row`] for a row the schema should not have allowed.
    pub fn intent_for_request(
        &self,
        origin_device: &str,
        request_id: &str,
    ) -> Result<Option<IntentRecord>, DbError> {
        let sql = format!(
            "SELECT {} FROM intents WHERE origin_device = ?1 AND request_id = ?2",
            columns::INTENT.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let mut rows = statement
            .query_map(params![origin_device, request_id], |row| {
                Ok(IntentRecord::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?.as_deref(),
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        match rows.next() {
            None => Ok(None),
            Some(row) => {
                let record = row
                    .map_err(|error| DbError::Statement { why: error.to_string() })?
                    .map_err(DbError::from)?;
                Ok(Some(record))
            }
        }
    }

    /// How many intents are stored.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the count cannot be read.
    pub fn intent_count(&self) -> Result<usize, DbError> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM intents", [], |row| row.get(0))
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// Forgets intents whose state is one of `finished` and which have not changed since `before_ms`.
    ///
    /// # Returns
    ///
    /// How many rows were removed, so a caller can report what it did rather than claim it did something.
    ///
    /// # Why the caller supplies the finished states
    ///
    /// Because they are the kernel's vocabulary. A store that hard-coded `"succeeded"` would be a second definition of
    /// what finished means, and the two would drift — the first time a state is renamed, one of them would keep working.
    ///
    /// # ★ Why the state has to match at all, rather than only the age
    ///
    /// Because an intent that is *still running* is not old data, however long it has been running. A collector that
    /// removed work in flight would lose it silently, and the user would be told nothing about something they asked for.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the delete is refused.
    pub fn forget_finished_intents(
        &self,
        finished: &[&str],
        before_ms: i64,
    ) -> Result<usize, DbError> {
        if finished.is_empty() {
            // Nothing is finished, so nothing is collected. Expressed as a positive branch rather than letting an empty
            // `IN ()` reach SQLite, which is a syntax error and would be reported as a database fault.
            return Ok(0);
        }
        // The placeholders are counted from the slice, and the values are bound rather than interpolated — a state name
        // is not a number, and a query assembled from strings is how one becomes SQL.
        let placeholders = (2..finished.len() + 2)
            .map(|position| format!("?{position}"))
            .collect::<Vec<String>>()
            .join(", ");
        let sql = format!(
            "DELETE FROM intents WHERE state IN ({placeholders}) AND updated_ms < ?1"
        );

        let mut values: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(finished.len() + 1);
        values.push(&before_ms);
        for state in finished {
            values.push(state);
        }

        timed_write!(self, "intent", {
            self.connection
                .execute(&sql, values.as_slice())
                .map_err(|error| DbError::Statement { why: error.to_string() })
        })
    }
}

#[cfg(test)]
mod tests;
