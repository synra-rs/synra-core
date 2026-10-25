//! A bounded pairing journal and independent, generation-bound authorization facts.

use rusqlite::{OptionalExtension, params};

use super::{DbError, SynraDb};

/// Snapshot of one pairing instance, captured before waiting for the user or external IO.
#[derive(Debug, Clone)]
pub struct PeerTrustAttempt {
    /// Unique local task identifier; never reused for a retry.
    pub request_id: String,
    /// Enrolled local device identifier.
    pub local_id: String,
    /// Exact public local credential, never its private key.
    pub local_certificate: Vec<u8>,
    /// Out-of-band approved and mutually authenticated peer identifier.
    pub peer_id: String,
    /// Exact approved public peer certificate.
    pub peer_certificate: Vec<u8>,
    /// RFC 9266 binding of this single pairing instance.
    pub binding: [u8; 32],
    /// Explicit epoch-millisecond task deadline; unfinished work cannot authorize after restart.
    pub expires_at_ms: i64,
}

/// A durable peer authorization; a fresh pairing always has a fresh generation.
#[derive(Debug, Clone)]
pub struct TrustedPeerRecord {
    /// Peer identifier.
    pub peer_id: String,
    /// Approved public certificate.
    pub certificate: Vec<u8>,
    /// The successful local task identifier, used to invalidate old connections on re-pairing.
    pub generation: String,
}

// All stage changes compare the entire original snapshot and the current enrolled local identity.
const CURRENT: &str = "request_id = ?1 AND local_id = ?2 AND local_certificate = ?3
    AND peer_id = ?4 AND peer_certificate = ?5 AND binding = ?6 AND expires_at_ms = ?7
    AND expires_at_ms > ?8 AND EXISTS (
        SELECT 1 FROM device_credentials c JOIN identity i ON i.id = c.id
        WHERE c.id = 1 AND c.ready = 1 AND c.device_id = ?2 AND i.device_id = ?2 AND c.certificate = ?3)";

impl SynraDb {
    /// Atomically claims the sole live pairing slot, refusing an already authorized peer or full list.
    ///
    /// Terminal or expired tasks may be replaced; their old snapshots can never commit the new task.
    /// # Errors
    /// Returns a database error for invalid data or failed IO; `false` is a refused claim.
    pub fn claim_peer_trust(
        &self,
        attempt: &PeerTrustAttempt,
        now_ms: i64,
        capacity: usize,
    ) -> Result<bool, DbError> {
        self.require_durable_trust()?;
        let capacity = i64::try_from(capacity).map_err(|_| DbError::Statement {
            why: "invalid peer trust capacity".to_owned(),
        })?;
        timed_write!(self, "peer-trust-claim", {
            self.connection.execute(
                "INSERT INTO pairing_attempt (id, request_id, local_id, local_certificate, peer_id, peer_certificate, binding, expires_at_ms, phase)
                 SELECT 1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0
                 WHERE ?7 > ?8 AND EXISTS (SELECT 1 FROM device_credentials c JOIN identity i ON i.id = c.id
                     WHERE c.id = 1 AND c.ready = 1 AND c.device_id = ?2 AND i.device_id = ?2 AND c.certificate = ?3)
                 AND NOT EXISTS (SELECT 1 FROM peer_trust WHERE peer_id = ?4)
                 AND (SELECT count(*) FROM peer_trust) < ?9
                 ON CONFLICT(id) DO UPDATE SET request_id = excluded.request_id, local_id = excluded.local_id,
                     local_certificate = excluded.local_certificate, peer_id = excluded.peer_id, peer_certificate = excluded.peer_certificate,
                     binding = excluded.binding, expires_at_ms = excluded.expires_at_ms, phase = 0
                 WHERE pairing_attempt.phase IN (2, 3) OR pairing_attempt.expires_at_ms <= ?8",
                params![attempt.request_id, attempt.local_id, attempt.local_certificate, attempt.peer_id, attempt.peer_certificate, attempt.binding.as_slice(), attempt.expires_at_ms, now_ms, capacity],
            ).map(|changed| changed == 1).map_err(|error| statement(&error))
        })
    }

    /// Checks a pending task against cancellation, expiry, snapshot changes and local enrollment.
    /// # Errors
    /// Returns a database error if the check cannot run.
    pub fn peer_attempt_current(
        &self,
        attempt: &PeerTrustAttempt,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        self.connection
            .query_row(
                &format!(
                    "SELECT 1 FROM pairing_attempt WHERE id = 1 AND phase IN (0, 1) AND {CURRENT}"
                ),
                params![
                    attempt.request_id,
                    attempt.local_id,
                    attempt.local_certificate,
                    attempt.peer_id,
                    attempt.peer_certificate,
                    attempt.binding.as_slice(),
                    attempt.expires_at_ms,
                    now_ms
                ],
                |_| Ok(true),
            )
            .optional()
            .map(|found| found.unwrap_or(false))
            .map_err(|error| statement(&error))
    }

    /// Durably marks mutual user consent, before any success receipt is sent to the peer.
    /// # Errors
    /// Returns a database error on failed persistence; `false` refuses a stale or cancelled task.
    pub fn store_peer_consent(
        &self,
        attempt: &PeerTrustAttempt,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        self.require_durable_trust()?;
        timed_write!(self, "peer-trust-store", {
            self.connection.execute(
                &format!("UPDATE pairing_attempt SET phase = 1 WHERE id = 1 AND phase = 0 AND {CURRENT}"),
                params![attempt.request_id, attempt.local_id, attempt.local_certificate, attempt.peer_id, attempt.peer_certificate, attempt.binding.as_slice(), attempt.expires_at_ms, now_ms],
            ).map(|changed| changed == 1).map_err(|error| statement(&error))
        })
    }

    /// Activates the unchanged prepared task only after matching mutual durable receipts.
    /// # Errors
    /// Returns a database error and rolls back on failure; `false` refuses a stale task.
    pub fn activate_peer_trust(
        &self,
        attempt: &PeerTrustAttempt,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        self.require_durable_trust()?;
        timed_write!(self, "peer-trust-activate", {
            let operation = || -> rusqlite::Result<bool> {
                let transaction = self.connection.unchecked_transaction()?;
                let changed = transaction.execute(
                    &format!("UPDATE pairing_attempt SET phase = 2 WHERE id = 1 AND phase = 1 AND {CURRENT}"),
                    params![attempt.request_id, attempt.local_id, attempt.local_certificate, attempt.peer_id, attempt.peer_certificate, attempt.binding.as_slice(), attempt.expires_at_ms, now_ms],
                )?;
                if changed != 1 {
                    return Ok(false);
                }
                transaction.execute(
                    "INSERT INTO peer_trust (peer_id, local_id, local_certificate, peer_certificate, generation, binding, confirmed_at_ms)
                     SELECT peer_id, local_id, local_certificate, peer_certificate, request_id, binding, ?2
                     FROM pairing_attempt WHERE id = 1 AND request_id = ?1 AND phase = 2",
                    params![attempt.request_id, now_ms],
                )?;
                transaction.commit()?;
                Ok(true)
            };
            operation().map_err(|error| statement(&error))
        })
    }

    /// Cancels only this task generation; dropping an old owner cannot cancel its replacement.
    /// # Errors
    /// Returns a database error if cancellation cannot be persisted.
    pub fn cancel_peer_attempt(&self, request_id: &str) -> Result<bool, DbError> {
        timed_write!(self, "peer-trust-cancel", {
            self.connection.execute("UPDATE pairing_attempt SET phase = 3 WHERE id = 1 AND request_id = ?1 AND phase IN (0, 1)", [request_id])
                .map(|changed| changed == 1).map_err(|error| statement(&error))
        })
    }

    /// Reads approvals only for the exact current enrolled local certificate.
    /// # Errors
    /// Returns a database error if authorization facts cannot be read.
    pub fn trusted_peer_records(
        &self,
        local_id: &str,
        local_certificate: &[u8],
    ) -> Result<Vec<TrustedPeerRecord>, DbError> {
        let mut query = self.connection.prepare(
            "SELECT peer_id, peer_certificate, generation FROM peer_trust WHERE local_id = ?1 AND local_certificate = ?2
             AND EXISTS (SELECT 1 FROM device_credentials c JOIN identity i ON i.id = c.id
                 WHERE c.id = 1 AND c.ready = 1 AND c.device_id = ?1 AND i.device_id = ?1 AND c.certificate = ?2)",
        ).map_err(|error| statement(&error))?;
        query
            .query_map(params![local_id, local_certificate], |row| {
                Ok(TrustedPeerRecord {
                    peer_id: row.get(0)?,
                    certificate: row.get(1)?,
                    generation: row.get(2)?,
                })
            })
            .map_err(|error| statement(&error))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| statement(&error))
    }

    /// Rechecks one captured authorization generation without loading the entire trust list.
    /// # Errors
    /// Returns a database error if the check cannot run; an absent or replaced grant returns `false`.
    pub fn peer_trust_current(
        &self,
        local_id: &str,
        local_certificate: &[u8],
        peer: &TrustedPeerRecord,
    ) -> Result<bool, DbError> {
        self.connection.query_row(
            "SELECT 1 FROM peer_trust WHERE local_id = ?1 AND local_certificate = ?2 AND peer_id = ?3 AND peer_certificate = ?4 AND generation = ?5
             AND EXISTS (SELECT 1 FROM device_credentials c JOIN identity i ON i.id = c.id
                 WHERE c.id = 1 AND c.ready = 1 AND c.device_id = ?1 AND i.device_id = ?1 AND c.certificate = ?2)",
            params![local_id, local_certificate, peer.peer_id, peer.certificate, peer.generation], |_| Ok(true),
        ).optional().map(|found| found.unwrap_or(false)).map_err(|error| statement(&error))
    }

    fn require_durable_trust(&self) -> Result<(), DbError> {
        let file = self.connection.path().is_some_and(|path| !path.is_empty());
        let sync: i64 = self
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(|error| statement(&error))?;
        let journal: String = self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|error| statement(&error))?;
        if !file || sync < 2 || journal != "wal" {
            return Err(DbError::Statement {
                why: "peer trust requires a file database with WAL and FULL commit synchronization"
                    .to_owned(),
            });
        }
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
