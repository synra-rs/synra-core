use rusqlite::{OptionalExtension, params};

use crate::records::IdentityRow;

use super::{DbError, SynraDb};

impl SynraDb {
    /// Creates the initial identity only if no other connection has already created one.
    ///
    /// # Errors
    /// Returns a database error if the insert fails; `false` preserves the existing identity unchanged.
    pub fn create_identity_if_absent(&self, identity: &IdentityRow) -> Result<bool, DbError> {
        timed_write!(self, "identity-create", {
            let transaction = rusqlite::Transaction::new_unchecked(
                &self.connection,
                rusqlite::TransactionBehavior::Immediate,
            )
            .map_err(|error| statement(&error))?;
            let initialized: bool = transaction
                .query_row(
                    "SELECT initialized FROM identity_bootstrap WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| statement(&error))?;
            let history: Option<String> = transaction
                .query_row(
                    "SELECT device_id FROM device_identity_history WHERE id = 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| statement(&error))?;
            let existing: bool = transaction
                .query_row("SELECT EXISTS (SELECT 1 FROM identity)", [], |row| {
                    row.get(0)
                })
                .map_err(|error| statement(&error))?;
            if !existing && initialized && history.is_none() {
                return Err(DbError::Statement {
                    why: "local identity history is missing; restore a trusted database backup"
                        .to_owned(),
                });
            }
            let device_id = history.as_deref().unwrap_or(&identity.device_id);
            let changed = transaction
                .execute(
                    "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms)
                 VALUES (1, ?1, ?2, ?3, ?4) ON CONFLICT(id) DO NOTHING",
                    params![
                        device_id,
                        identity.display_name,
                        identity.platform,
                        identity.created_at_ms
                    ],
                )
                .map_err(|error| statement(&error))?;
            if !initialized {
                transaction
                    .execute(
                        "INSERT INTO device_identity_history (id, device_id)
                     SELECT id, device_id FROM identity WHERE id = 1 ON CONFLICT(id) DO NOTHING",
                        [],
                    )
                    .map_err(|error| statement(&error))?;
                transaction
                    .execute(
                        "UPDATE identity_bootstrap SET initialized = 1 WHERE id = 1",
                        [],
                    )
                    .map_err(|error| statement(&error))?;
            }
            transaction.commit().map_err(|error| statement(&error))?;
            Ok(changed == 1)
        })
    }

    /// This device's identity, if it has one.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn identity(&self) -> Result<Option<IdentityRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM identity WHERE id = 1",
            crate::records::columns::IDENTITY.join(", ")
        );
        // The four values are bound before the call, because `as_deref()` on a temporary would borrow a `String` that is
        // dropped at the end of the expression — and `from_columns` needs the borrows to outlive it.
        let row = self
            .connection
            .query_row(&sql, [], |row| {
                let device_id: Option<String> = row.get(0)?;
                let display_name: Option<String> = row.get(1)?;
                let platform: Option<String> = row.get(2)?;
                let created_at_ms: Option<i64> = row.get(3)?;
                Ok(IdentityRow::from_columns(
                    device_id.as_deref(),
                    display_name.as_deref(),
                    platform.as_deref(),
                    created_at_ms,
                ))
            })
            .optional()
            .map_err(|error| DbError::Statement {
                why: error.to_string(),
            })?;

        match row {
            Some(Ok(identity)) => Ok(Some(identity)),
            Some(Err(error)) => Err(DbError::Row(error)),
            None => Ok(None),
        }
    }

    /// Creates or restores an identity, or updates metadata for the same immutable device id.
    ///
    /// Missing identities use the initialization/history gate; metadata updates cannot reinsert a
    /// concurrently deleted row or replace another identity.
    /// # Errors
    /// Refuses an identity mismatch, lost recovery history or failed persistence.
    pub fn write_identity(&self, identity: &IdentityRow) -> Result<(), DbError> {
        if self.create_identity_if_absent(identity)? {
            return Ok(());
        }
        timed_write!(self, "identity", {
            let changed = self.connection.execute(
                "UPDATE identity SET display_name = ?2, platform = ?3 WHERE id = 1 AND device_id = ?1",
                params![identity.device_id, identity.display_name, identity.platform],
            ).map_err(|error| statement(&error))?;
            if changed != 1 {
                return Err(DbError::Statement {
                    why: "local identity changed before metadata update".to_owned(),
                });
            }
            Ok(())
        })
    }
}

fn statement(error: &rusqlite::Error) -> DbError {
    DbError::Statement {
        why: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialized() -> SynraDb {
        let mut db = SynraDb::open_in_memory().unwrap();
        db.migrate().unwrap();
        let row = IdentityRow::from_columns(Some("original"), Some("First"), Some("test"), Some(1))
            .unwrap();
        db.create_identity_if_absent(&row).unwrap();
        db
    }

    fn proposed() -> IdentityRow {
        IdentityRow::from_columns(Some("different"), Some("Restored"), Some("test"), Some(2))
            .unwrap()
    }

    #[test]
    fn missing_identity_restores_the_retained_device_id_without_restoring_authority() {
        let db = initialized();
        db.claim_device_credential("original", b"certificate", "test")
            .unwrap();
        db.connection.execute("DELETE FROM identity", []).unwrap();
        assert!(db.device_credential().unwrap().is_none());
        assert!(db.create_identity_if_absent(&proposed()).unwrap());
        assert_eq!(db.identity().unwrap().unwrap().device_id, "original");
        assert!(
            !db.claim_device_credential("original", b"new certificate", "test")
                .unwrap()
        );
        let state = db.device_credential_state().unwrap().unwrap();
        assert!(state.enrollment.is_none());
        assert_eq!(
            state.recovery_enrollment.unwrap().certificate(),
            b"certificate"
        );
    }

    #[test]
    fn loss_before_first_enrollment_preserves_id_and_can_finish_initial_setup() {
        let db = initialized();
        db.connection.execute("DELETE FROM identity", []).unwrap();
        db.write_identity(&proposed()).unwrap();
        assert_eq!(db.identity().unwrap().unwrap().device_id, "original");
        assert!(
            db.claim_device_credential("original", b"first", "test")
                .unwrap()
        );
    }

    #[test]
    fn missing_identity_and_history_refuse_both_creation_entry_points() {
        let db = initialized();
        db.connection
            .execute_batch("DELETE FROM identity; DELETE FROM device_identity_history;")
            .unwrap();
        assert!(db.create_identity_if_absent(&proposed()).is_err());
        assert!(db.write_identity(&proposed()).is_err());
        assert!(db.identity().unwrap().is_none());
    }

    #[test]
    fn metadata_updates_cannot_replace_the_stable_device_id() {
        let db = initialized();
        assert!(db.write_identity(&proposed()).is_err());
        let mut same = db.identity().unwrap().unwrap();
        same.display_name = "Renamed".to_owned();
        db.write_identity(&same).unwrap();
        assert_eq!(db.identity().unwrap().unwrap(), same);
    }

    #[test]
    fn initialization_cannot_be_forgotten_or_reset() {
        let db = initialized();
        assert!(
            db.connection
                .execute("DELETE FROM identity_bootstrap", [])
                .is_err()
        );
        assert!(
            db.connection
                .execute("UPDATE identity_bootstrap SET initialized = 0", [])
                .is_err()
        );
    }

    #[test]
    fn concurrent_initial_claims_both_observe_one_durable_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.sqlite");
        let mut db = SynraDb::open(&path).unwrap();
        db.migrate().unwrap();
        let left = SynraDb::open(&path).unwrap();
        let right = SynraDb::open(&path).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            for (connection, id) in [(left, "left"), (right, "right")] {
                let sender = sender.clone();
                let barrier = &barrier;
                scope.spawn(move || {
                    let row =
                        IdentityRow::from_columns(Some(id), Some("Device"), Some("test"), Some(1))
                            .unwrap();
                    barrier.wait();
                    let claimed = connection.create_identity_if_absent(&row).unwrap();
                    sender.send((id, claimed)).unwrap();
                });
            }
            let first = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            let second = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert_ne!(first.1, second.1);
            let winner = if first.1 { first.0 } else { second.0 };
            assert_eq!(db.identity().unwrap().unwrap().device_id, winner);
        });
    }

    #[test]
    fn a_losing_initial_identity_claim_preserves_the_winner() {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("migrate");
        let winner =
            IdentityRow::from_columns(Some("winner"), Some("First"), Some("windows"), Some(1))
                .expect("row");
        let loser =
            IdentityRow::from_columns(Some("loser"), Some("Second"), Some("android"), Some(2))
                .expect("row");
        assert!(
            db.create_identity_if_absent(&winner)
                .expect("initial claim")
        );
        assert!(!db.create_identity_if_absent(&loser).expect("losing claim"));
        assert_eq!(db.identity().expect("read"), Some(winner));
    }
}
