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
        self.connection
            .execute(
                "INSERT INTO intents \
                     (intent_id, origin, plugin_id, action, args, state, created_ms, updated_ms, expires_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT (intent_id) DO UPDATE SET \
                     origin = ?2, \
                     plugin_id = ?3, \
                     action = ?4, \
                     args = ?5, \
                     state = ?6, \
                     -- ★ `created_ms` is deliberately absent: it is when the intent was raised, and a later write is not
                     -- a later raising. Overwriting it would make every intent look as though it had just started.
                     updated_ms = ?8, \
                     expires_ms = ?9",
                params![
                    intent.intent_id.as_str(),
                    intent.origin.as_str(),
                    intent.plugin_id.as_str(),
                    intent.action.as_str(),
                    intent.args.as_str(),
                    intent.state.as_str(),
                    intent.created_ms,
                    intent.updated_ms,
                    intent.expires_ms,
                ],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
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
                    crate::records::IntentText {
                        intent_id: row.get::<_, Option<String>>(0)?.as_deref(),
                        origin: row.get::<_, Option<String>>(1)?.as_deref(),
                        plugin_id: row.get::<_, Option<String>>(2)?.as_deref(),
                        action: row.get::<_, Option<String>>(3)?.as_deref(),
                        args: row.get::<_, Option<String>>(4)?.as_deref(),
                        state: row.get::<_, Option<String>>(5)?.as_deref(),
                    },
                    crate::records::IntentNumbers {
                        created_ms: row.get::<_, Option<i64>>(6)?,
                        updated_ms: row.get::<_, Option<i64>>(7)?,
                        expires_ms: row.get::<_, Option<i64>>(8)?,
                    },
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<IntentRecord, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<IntentRecord>, RowError>>().map_err(DbError::from)
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

        self.connection
            .execute(&sql, values.as_slice())
            .map_err(|error| DbError::Statement { why: error.to_string() })
    }
}

#[cfg(test)]
mod tests;
