//! Persisted retry schedules for dispatches nobody has answered.
//!
//! # Why this is a table and not part of the intent document
//!
//! Because the schedule is not part of the intent. The kernel's `Intent` is what the *user* asked for, and it is written by
//! the kernel; how many times one host has tried to deliver it is a fact about that host's effort, and putting it into the
//! document would make every host reading the intent see someone else's retry count. A separate row keyed by the intent
//! says exactly that, and `ON DELETE CASCADE` means it cannot outlive what it describes.
//!
//! # What the row is for
//!
//! So a restart continues the backoff instead of starting it over. The attempts are the process's own, so the row is
//! deliberately small: no request id (the intent has it), no target (the intent has it), no envelope (the kernel rebuilds
//! it). A schedule that repeated any of those would be a second copy free to disagree.

use rusqlite::params;

use super::{DbError, SynraDb};

/// One persisted retry schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRetryRow {
    /// The intent this schedule belongs to.
    pub intent_id: String,
    /// How many times the host has already sent it again.
    pub attempts: u32,
    /// When the next attempt is due, in milliseconds since the epoch. `None` for a given-up schedule.
    pub next_at_ms: Option<i64>,
    /// Whether the host stopped retrying. The intent itself is still in flight; this is about the effort.
    pub gave_up: bool,
}

impl SynraDb {
    /// Writes a schedule, or replaces the one under the same intent.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused — including a foreign key for an intent that is not stored, which
    /// is the check that keeps a schedule from outliving its intent.
    pub fn save_intent_retry(&self, row: &IntentRetryRow) -> Result<(), DbError> {
        timed_write!(self, "intent", {
            self.connection
                .execute(
                    "INSERT INTO intent_retries (intent_id, attempts, next_at_ms, gave_up) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (intent_id) DO UPDATE SET \
                         attempts = ?2, \
                         next_at_ms = ?3, \
                         gave_up = ?4",
                    params![
                        row.intent_id,
                        i64::from(row.attempts),
                        row.next_at_ms,
                        if row.gave_up { 1_i64 } else { 0_i64 },
                    ],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
    }

    /// Every persisted schedule, ordered by intent so two runs agree.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the rows cannot be read, or [`DbError::Row`] for a count the schema should not allow.
    pub fn load_intent_retries(&self) -> Result<Vec<IntentRetryRow>, DbError> {
        let mut statement = self
            .connection
            .prepare("SELECT intent_id, attempts, next_at_ms, gave_up FROM intent_retries ORDER BY intent_id")
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter()
            .map(|(intent_id, attempts, next_at_ms, gave_up)| {
                let attempts = u32::try_from(attempts).map_err(|_| DbError::Statement {
                    why: format!("intent {intent_id} has an attempt count that is not a number of attempts: {attempts}"),
                })?;
                Ok(IntentRetryRow { intent_id, attempts, next_at_ms, gave_up: gave_up != 0 })
            })
            .collect()
    }

    /// Removes one schedule.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the delete is refused. A missing row is not an error: "this intent is not being
    /// retried" is satisfied by there being nothing.
    pub fn forget_intent_retry(&self, intent_id: &str) -> Result<(), DbError> {
        timed_write!(self, "intent", {
            self.connection
                .execute("DELETE FROM intent_retries WHERE intent_id = ?1", params![intent_id])
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("a database");
        db.migrate().expect("migrates");
        // A schedule needs its intent to exist: the foreign key is part of what this table promises.
        db.connection
            .execute(
                "INSERT INTO intents (intent_id, state, created_ms, updated_ms, document) \
                 VALUES ('intent-a', 'dispatching', 1, 1, '{}')",
                [],
            )
            .expect("an intent");
        db
    }

    #[test]
    fn a_schedule_round_trips_and_is_replaced_rather_than_duplicated() {
        let db = database();
        db.save_intent_retry(&IntentRetryRow {
            intent_id: "intent-a".to_owned(),
            attempts: 3,
            next_at_ms: Some(10_000),
            gave_up: false,
        })
        .expect("stored");
        db.save_intent_retry(&IntentRetryRow {
            intent_id: "intent-a".to_owned(),
            attempts: 4,
            next_at_ms: None,
            gave_up: true,
        })
        .expect("replaced");

        let rows = db.load_intent_retries().expect("readable");
        assert_eq!(rows.len(), 1, "one row per intent, not one per write");
        assert_eq!(rows[0].attempts, 4);
        assert_eq!(rows[0].next_at_ms, None);
        assert!(rows[0].gave_up);
    }

    #[test]
    fn a_schedule_for_an_intent_that_is_not_there_is_refused() {
        // ★ The foreign key is the sentence "a retry cannot outlive its intent"; without it the table would grow rows
        // nothing can join, and the loop would keep scheduling work that does not exist.
        let db = database();
        let refused = db.save_intent_retry(&IntentRetryRow {
            intent_id: "ghost".to_owned(),
            attempts: 1,
            next_at_ms: Some(1),
            gave_up: false,
        });
        assert!(refused.is_err());
    }

    #[test]
    fn forgetting_a_schedule_that_is_not_there_is_not_an_error() {
        let db = database();
        db.forget_intent_retry("ghost").expect("nothing to delete is the asked-for state");
        assert!(db.load_intent_retries().expect("readable").is_empty());
    }

    #[test]
    fn deleting_the_intent_deletes_its_schedule() {
        let db = database();
        db.save_intent_retry(&IntentRetryRow {
            intent_id: "intent-a".to_owned(),
            attempts: 1,
            next_at_ms: Some(1),
            gave_up: false,
        })
        .expect("stored");

        db.connection.execute("DELETE FROM intents WHERE intent_id = 'intent-a'", []).expect("deleted");
        assert!(
            db.load_intent_retries().expect("readable").is_empty(),
            "the schedule went with the intent"
        );
    }
}
