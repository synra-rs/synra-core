//! Recording a pairing, and answering what a presented token means.
//!
//! # Why the token is queried on its own rather than carried on [`DeviceRow`](crate::records::DeviceRow)
//!
//! Because it is a secret. `DeviceRow` is what a device list is built from and what reaches the interface, so a field
//! there is a field a screen can render and a log line can print. The token has exactly one consumer — the handshake's
//! "is this the device I paired with" question — and it is read one row at a time, only when someone dials.
//!
//! # Why recording a pairing is an upsert
//!
//! Because pairing the same device twice is an ordinary thing to do: a device is reset, or its token is refused as
//! stale, and the user pairs it again. An `INSERT` that failed on the second attempt would turn a routine action into an
//! error, and the useful state — the new token, the new time — is exactly what the second pairing establishes.

use rusqlite::params;

use super::{DbError, SynraDb};

/// What a pairing recorded, for a caller that has to report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    /// The device's identifier, as the handshake established it.
    pub device_id: String,
    /// The name the device gave.
    pub display_name: String,
    /// The features the two ends agreed on, as the JSON array the column holds.
    pub features: String,
    /// When the pairing was recorded.
    pub paired_at_ms: i64,
}

impl SynraDb {
    /// Records a pairing, or replaces the token of one that already exists.
    ///
    /// `address` is where the peer was reached or last heard from, as `host:port`, and an empty string records no
    /// address: a caller with no socket under it — a local pairing, or a test — has nothing to store, and a column
    /// holding `""` is one every reader would have to treat as absent anyway.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the row cannot be written, which for a well-formed argument means the table is absent.
    pub fn pair_device(
        &self,
        device_id: &str,
        display_name: &str,
        platform: &str,
        features: &str,
        link_token: &str,
        address: &str,
        now_ms: i64,
    ) -> Result<Paired, DbError> {
        let address = if address.is_empty() { None } else { Some(address) };
        self.connection
            .execute(
                "INSERT INTO paired_devices \
                     (device_id, display_name, platform, features, link_token, last_address, \
                      paired_at_ms, last_seen_ms, blocked) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 0) \
                 ON CONFLICT(device_id) DO UPDATE SET \
                     display_name = excluded.display_name, \
                     platform     = excluded.platform, \
                     features     = excluded.features, \
                     link_token   = excluded.link_token, \
                     last_address = excluded.last_address, \
                     paired_at_ms = excluded.paired_at_ms, \
                     last_seen_ms = excluded.last_seen_ms, \
                     blocked      = 0",
                params![device_id, display_name, platform, features, link_token, address, now_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        Ok(Paired {
            device_id: device_id.to_owned(),
            display_name: display_name.to_owned(),
            features: features.to_owned(),
            paired_at_ms: now_ms,
        })
    }

    /// The token an outside dialler must present for `device_id`, if this device is paired with it.
    ///
    /// # Returns
    ///
    /// `None` when there is no paired row, which the handshake reports as a first-time pairing rather than a refusal.
    /// A row whose token is `NULL` also answers `None`: the pairing exists but predates tokens, and the handshake
    /// reports that as `Stale` rather than as a refusal, so the user can pair again instead of being told "no".
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the query cannot run.
    pub fn link_token_for(&self, device_id: &str) -> Result<Option<String>, DbError> {
        let mut statement = self
            .connection
            .prepare("SELECT link_token FROM paired_devices WHERE device_id = ?1")
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let mut rows = statement
            .query(params![device_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        match rows.next() {
            // No row is an answer, not a failure: it means this device was never paired with that one.
            Ok(None) => Ok(None),
            Ok(Some(row)) => row
                .get::<_, Option<String>>(0)
                .map_err(|error| DbError::Statement { why: error.to_string() }),
            Err(error) => Err(DbError::Statement { why: error.to_string() }),
        }
    }

    /// Whether a device is paired, without reading its token.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the query cannot run.
    pub fn is_paired_with(&self, device_id: &str) -> Result<bool, DbError> {
        self.connection
            .query_row(
                "SELECT 1 FROM paired_devices WHERE device_id = ?1 AND blocked = 0",
                params![device_id],
                |_| Ok(()),
            )
            .map(|()| true)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(DbError::Statement { why: other.to_string() }),
            })
    }

    /// Removes a pairing, and the token that belonged to it.
    ///
    /// # Returns
    ///
    /// Whether a row was removed, so a caller can tell "unpaired" from "was not paired".
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the delete cannot run.
    pub fn unpair_device(&self, device_id: &str) -> Result<bool, DbError> {
        let removed = self
            .connection
            .execute("DELETE FROM paired_devices WHERE device_id = ?1", params![device_id])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(removed > 0)
    }
}
