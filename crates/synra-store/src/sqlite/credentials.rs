//! Durable public enrollment marker; private keys are never stored in SQLite.

use rusqlite::{OptionalExtension, params};

use super::{DbError, SynraDb};

/// The public half of a device credential enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCredentialRecord {
    device_id: String,
    certificate: Vec<u8>,
    backend: String,
    ready: bool,
}

impl DeviceCredentialRecord {
    /// Device id this enrollment belongs to.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Public certificate DER; this record contains no private key.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Secret backend selected at enrollment; loading must not silently switch it.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Whether private-key readback and validation have committed.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready
    }
}

impl SynraDb {
    /// Reads the public enrollment marker, including incomplete enrollments.
    ///
    /// # Errors
    /// Returns a database error if the marker cannot be read.
    pub fn device_credential(&self) -> Result<Option<DeviceCredentialRecord>, DbError> {
        self.connection.query_row(
            "SELECT device_id, certificate, backend, ready FROM device_credentials WHERE id = 1",
            [],
            |row| Ok(DeviceCredentialRecord { device_id: row.get(0)?, certificate: row.get(1)?, backend: row.get(2)?, ready: row.get(3)? }),
        ).optional().map_err(|error| statement(&error))
    }

    /// Claims a new enrollment before any private key is written outside SQLite.
    ///
    /// Exactly one contender wins. The current local id must match and no old pairing may exist;
    /// enrollment never attaches a new key to existing grants. No secret backend runs in this statement.
    ///
    /// # Errors
    /// Returns a database error for invalid data or failed IO; `false` means the claim was refused.
    pub fn claim_device_credential(
        &self,
        device_id: &str,
        certificate: &[u8],
        backend: &str,
    ) -> Result<bool, DbError> {
        timed_write!(self, "device-credential-claim", {
            let changed = self.connection.execute(
            "INSERT INTO device_credentials (id, device_id, certificate, backend, ready)
             SELECT 1, ?1, ?2, ?3, 0 WHERE EXISTS (SELECT 1 FROM identity WHERE id = 1 AND device_id = ?1)
             AND NOT EXISTS (SELECT 1 FROM paired_devices)
             ON CONFLICT(id) DO NOTHING",
            params![device_id, certificate, backend],
        ).map_err(|error| statement(&error))?;
            Ok(changed == 1)
        })
    }

    /// Commits validated key readback, or rechecks an already ready enrollment against current identity.
    ///
    /// Used after secret-store IO with no database lock held; stale snapshots cannot commit.
    ///
    /// # Errors
    /// Returns a database error if the commit fails; `false` means the enrollment or local id changed.
    pub fn finish_device_credential(
        &self,
        expected: &DeviceCredentialRecord,
    ) -> Result<bool, DbError> {
        timed_write!(self, "device-credential-finish", {
            let changed = self
                .connection
                .execute(
                    "UPDATE device_credentials SET ready = 1 WHERE id = 1 AND device_id = ?1
             AND certificate = ?2 AND backend = ?3
             AND EXISTS (SELECT 1 FROM identity WHERE id = 1 AND device_id = ?1)",
                    params![expected.device_id, expected.certificate, expected.backend],
                )
                .map_err(|error| statement(&error))?;
            Ok(changed == 1)
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
    use crate::IdentityRow;

    fn database() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("migrate");
        let identity =
            IdentityRow::from_columns(Some("local"), Some("Local"), Some("windows"), Some(1))
                .expect("identity");
        db.create_identity_if_absent(&identity).expect("create");
        db
    }

    #[test]
    fn certificate_size_limits_are_enforced_by_sqlite() {
        let db = database();
        for certificate in [Vec::new(), vec![0; 16_385]] {
            assert!(
                db.claim_device_credential("local", &certificate, "windows")
                    .is_err()
            );
            assert!(db.device_credential().expect("read").is_none());
        }
        assert!(
            db.claim_device_credential("local", &vec![0; 16_384], "windows")
                .expect("bounded")
        );
    }

    #[test]
    fn a_replaced_public_marker_cannot_commit_an_old_readback() {
        let db = database();
        assert!(
            db.claim_device_credential("local", b"first certificate", "windows")
                .expect("claim")
        );
        let stale = db.device_credential().expect("read").expect("marker");
        db.connection
            .execute("DELETE FROM device_credentials", [])
            .expect("explicit repair");
        assert!(
            db.claim_device_credential("local", b"replacement certificate", "windows")
                .expect("replacement")
        );
        assert!(!db.finish_device_credential(&stale).expect("stale commit"));
        let current = db.device_credential().expect("read").expect("current");
        assert!(!current.ready());
        assert!(
            db.finish_device_credential(&current)
                .expect("current commit")
        );
        assert!(
            db.device_credential()
                .expect("read")
                .expect("ready")
                .ready()
        );
    }
}
