//! Atomic identity-key replacement and a bounded durable queue for retired secret slots.

use rusqlite::{OptionalExtension, params};

use super::{DbError, DeviceCredentialRecord, SynraDb};

/// Maximum retired secret slots retained before a further explicit repair must wait for cleanup.
pub const MAX_RETIRED_DEVICE_CREDENTIALS: u32 = 16;

/// Public metadata for a retired key; private key bytes never enter SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredDeviceCredential {
    /// Certificate whose fingerprint names the old secret slot.
    pub certificate: Vec<u8>,
    /// Backend in which that slot was originally enrolled.
    pub backend: String,
}

impl SynraDb {
    /// Names the persistent sidecar lock shared by credential writers for this database.
    /// # Errors
    /// Refuses ephemeral storage; callers acquire the lock after releasing the database guard.
    pub fn device_credential_lock_path(&self) -> Result<std::path::PathBuf, DbError> {
        let path = self
            .connection
            .path()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| DbError::Statement {
                why: "credential operations require a file database".to_owned(),
            })?;
        let mut path = std::path::PathBuf::from(path).into_os_string();
        path.push(".credential.lock");
        Ok(path.into())
    }

    /// Replaces the exact displayed enrollment and revokes all old grants and unfinished pairings.
    ///
    /// The replacement remains unready until secret writeback is validated. Failure rolls back
    /// revocation too; a stale expected marker or a full cleanup queue returns false without writes.
    /// # Errors
    /// Refuses non-durable storage, malformed records and failed database commits.
    pub fn replace_device_credential(
        &self,
        expected: &DeviceCredentialRecord,
        certificate: &[u8],
        backend: &str,
    ) -> Result<bool, DbError> {
        self.require_durable_trust()?;
        timed_write!(self, "device-credential-repair", {
            let transaction = self
                .connection
                .unchecked_transaction()
                .map_err(|error| statement(&error))?;
            // A surviving active registration can explicitly rebuild lost non-authorizing history.
            transaction.execute(
                "INSERT INTO device_identity_history (id, device_id, certificate, backend)
                 SELECT 1, ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM device_credentials
                     WHERE id = 1 AND device_id = ?1 AND certificate = ?2 AND backend = ?3 AND ready = ?4)
                 ON CONFLICT(id) DO NOTHING",
                params![expected.device_id(), expected.certificate(), expected.backend(), expected.ready()],
            ).map_err(|error| statement(&error))?;
            let changed = transaction
                .execute(
                    "UPDATE device_identity_history SET certificate = ?5, backend = ?6
                 WHERE id = 1 AND device_id = ?1 AND certificate = ?2 AND backend = ?3
                 AND EXISTS (SELECT 1 FROM identity WHERE id = 1 AND device_id = ?1)
                 AND (NOT EXISTS (SELECT 1 FROM device_credentials) OR EXISTS
                    (SELECT 1 FROM device_credentials WHERE id = 1 AND device_id = ?1
                     AND certificate = ?2 AND backend = ?3 AND ready = ?4))
                 AND certificate != ?5
                 AND NOT EXISTS (SELECT 1 FROM retired_device_credentials WHERE certificate = ?5)
                 AND (SELECT COUNT(*) FROM retired_device_credentials) < ?7",
                    params![
                        expected.device_id(),
                        expected.certificate(),
                        expected.backend(),
                        expected.ready(),
                        certificate,
                        backend,
                        MAX_RETIRED_DEVICE_CREDENTIALS
                    ],
                )
                .map_err(|error| statement(&error))?;
            if changed != 1 {
                return Ok(false);
            }
            transaction.execute(
                "INSERT INTO device_credentials (id, device_id, certificate, backend, ready) VALUES (1, ?1, ?2, ?3, 0)
                 ON CONFLICT(id) DO UPDATE SET device_id = excluded.device_id, certificate = excluded.certificate,
                    backend = excluded.backend, ready = 0",
                params![expected.device_id(), certificate, backend],
            ).map_err(|error| statement(&error))?;
            transaction
                .execute(
                    "INSERT INTO retired_device_credentials (certificate, backend) VALUES (?1, ?2)",
                    params![expected.certificate(), expected.backend()],
                )
                .map_err(|error| statement(&error))?;
            transaction
                .execute("DELETE FROM peer_trust", [])
                .map_err(|error| statement(&error))?;
            transaction
                .execute("DELETE FROM paired_devices", [])
                .map_err(|error| statement(&error))?;
            transaction
                .execute("DELETE FROM pairing_attempt", [])
                .map_err(|error| statement(&error))?;
            transaction.commit().map_err(|error| statement(&error))?;
            Ok(true)
        })
    }

    /// Lists the bounded durable cleanup queue without exposing a private key.
    /// # Errors
    /// Returns a database error if the queue cannot be read.
    pub fn retired_device_credentials(&self) -> Result<Vec<RetiredDeviceCredential>, DbError> {
        let mut query = self.connection.prepare(
            "SELECT certificate, backend FROM retired_device_credentials ORDER BY backend, certificate",
        ).map_err(|error| statement(&error))?;
        let rows = query
            .query_map([], |row| {
                Ok(RetiredDeviceCredential {
                    certificate: row.get(0)?,
                    backend: row.get(1)?,
                })
            })
            .map_err(|error| statement(&error))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| statement(&error))
    }

    /// Rechecks that cleanup targets a retired slot rather than any current enrollment.
    /// # Errors
    /// Refuses an unreadable database.
    pub fn device_credential_retired(
        &self,
        record: &RetiredDeviceCredential,
    ) -> Result<bool, DbError> {
        self.connection.query_row(
            "SELECT 1 FROM retired_device_credentials WHERE certificate = ?1 AND backend = ?2
             AND NOT EXISTS (SELECT 1 FROM device_credentials WHERE certificate = ?1 AND backend = ?2)
             AND NOT EXISTS (SELECT 1 FROM device_identity_history WHERE certificate = ?1 AND backend = ?2)",
            params![record.certificate, record.backend], |_| Ok(true),
        ).optional().map(|found| found.unwrap_or(false)).map_err(|error| statement(&error))
    }

    /// Acknowledges deletion only after external backend IO has succeeded.
    /// # Errors
    /// Returns a database error if acknowledgment fails; repeated secret deletion must be idempotent.
    pub fn finish_retired_device_credential(
        &self,
        record: &RetiredDeviceCredential,
    ) -> Result<(), DbError> {
        self.connection.execute(
            "DELETE FROM retired_device_credentials WHERE certificate = ?1 AND backend = ?2
             AND NOT EXISTS (SELECT 1 FROM device_credentials WHERE certificate = ?1 AND backend = ?2)
             AND NOT EXISTS (SELECT 1 FROM device_identity_history WHERE certificate = ?1 AND backend = ?2)",
            params![record.certificate, record.backend],
        ).map_err(|error| statement(&error))?;
        Ok(())
    }
}

fn statement(error: &rusqlite::Error) -> DbError {
    DbError::Statement {
        why: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
