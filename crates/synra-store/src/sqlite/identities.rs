use rusqlite::{OptionalExtension, params};

use crate::records::IdentityRow;

use super::{DbError, SynraDb};

impl SynraDb {
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
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        match row {
            Some(Ok(identity)) => Ok(Some(identity)),
            Some(Err(error)) => Err(DbError::Row(error)),
            None => Ok(None),
        }
    }

    /// Writes this device's identity, creating it or replacing it.
    ///
    /// # Why an upsert rather than an insert
    ///
    /// The schema declares `id INTEGER PRIMARY KEY CHECK (id = 1)`, which is what makes "this device's identity" a single
    /// answer — and an `INSERT` on the second call would be a second row, which the check refuses. So the row is at a
    /// fixed id and the write replaces it.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn write_identity(&self, identity: &IdentityRow) -> Result<(), DbError> {
        timed_write!(self, "identity", {
            self.connection
                .execute(
                    "INSERT INTO identity (id, device_id, display_name, platform, created_at_ms) \
                     VALUES (1, ?1, ?2, ?3, ?4) \
                     ON CONFLICT(id) DO UPDATE SET \
                         device_id = excluded.device_id, \
                         display_name = excluded.display_name, \
                         platform = excluded.platform",
                    params![
                        identity.device_id,
                        identity.display_name,
                        identity.platform,
                        identity.created_at_ms
                    ],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
    }
}
