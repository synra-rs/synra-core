//! Who signs packages, and what this device has decided about them.
//!
//! # Why this is a table rather than a settings key
//!
//! Because a trust decision is about a **key**, not a string: the same publisher id can be signed with a different key,
//! and that is exactly the case the design says must not be trusted. A settings row holding a list of ids could not
//! express the distinction, so the key, the fingerprint and the decision live together in one row.

use rusqlite::params;

use super::DbError;

use super::SynraDb;

/// The value of `trust` for a publisher whose signature has been seen but never judged.
pub const TRUST_SEEN: &str = "seen";
/// The value of `trust` for a publisher the user accepted.
pub const TRUST_TRUSTED: &str = "trusted";
/// The value of `trust` for a key the user refused.
pub const TRUST_REVOKED: &str = "revoked";

/// One publisher this device has met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherRow {
    /// The publisher's own identifier, from its signature.
    pub publisher_id: String,
    /// The key's fingerprint, as [`synra_plugin_api::publisher::Fingerprint`] prints it.
    pub fingerprint: String,
    /// The public key, base64, so the fingerprint can be recomputed.
    pub pubkey: String,
    /// One of [`TRUST_SEEN`], [`TRUST_TRUSTED`], [`TRUST_REVOKED`].
    pub trust: String,
    /// When the signature was first seen, in milliseconds since the epoch.
    pub first_seen_ms: i64,
    /// When the user decided, if they have.
    pub decided_ms: Option<i64>,
}

impl SynraDb {
    /// Every publisher, ordered by identifier.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the rows cannot be read.
    pub fn publishers(&self) -> Result<Vec<PublisherRow>, DbError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT publisher_id, fingerprint, pubkey, trust, first_seen_ms, decided_ms \
                 FROM publishers ORDER BY publisher_id",
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(PublisherRow {
                    publisher_id: row.get(0)?,
                    fingerprint: row.get(1)?,
                    pubkey: row.get(2)?,
                    trust: row.get(3)?,
                    first_seen_ms: row.get(4)?,
                    decided_ms: row.get(5)?,
                })
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<PublisherRow>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(rows)
    }

    /// Records a publisher whose signature was seen, keeping any decision already made.
    ///
    /// # Why `DO NOTHING`
    ///
    /// Because "this key signed a package" is not a judgement, and an install must not be able to *promote* a key — the
    /// only path to `trusted` is a user saying so. It must not demote one either: a trusted publisher's next install is
    /// the ordinary case, and it would otherwise reset the decision on every update.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn record_publisher(
        &self,
        publisher_id: &str,
        fingerprint: &str,
        pubkey: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        timed_write!(self, "publisher", {
            self.connection
                .execute(
                    "INSERT INTO publishers (publisher_id, fingerprint, pubkey, trust, first_seen_ms, decided_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL) \
                     ON CONFLICT (publisher_id) DO NOTHING",
                    params![publisher_id, fingerprint, pubkey, TRUST_SEEN, now_ms],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
    }

    /// Sets the decision for a publisher the device has met.
    ///
    /// Returns whether a row was updated. A publisher nobody has seen cannot be trusted: a decision about a key with no
    /// signature behind it would be a row the installer never consults.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn set_publisher_trust(
        &self,
        publisher_id: &str,
        trust: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        timed_write!(self, "publisher", {
            let changed = self
                .connection
                .execute(
                    "UPDATE publishers SET trust = ?2, decided_ms = ?3 WHERE publisher_id = ?1",
                    params![publisher_id, trust, now_ms],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(changed > 0)
        })
    }
}
