use rusqlite::params;

use crate::records::{DeviceRow, RowError, Seen, SeenDeviceRow};

use super::{DbError, SynraDb};

impl SynraDb {
    /// Records that a device was heard from, or refreshes the record of one that already was.
    ///
    /// # Why this is an upsert keyed on the device rather than on the sighting
    ///
    /// Because discovery announces the same machine on every scan, and one row per announcement would be a table that
    /// grows without bound for a device sitting on the same desk. What matters is *when it was last heard*, which is the
    /// one value that changes — and `first_seen_ms` is written only when the row is new, so it stays the first time.
    ///
    /// # Why `source` is carried rather than inferred
    ///
    /// Because "which network path heard this" is what a user is told when a device turns out to be unreachable, and a
    /// value invented at read time would be a guess about where the row came from.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn record_seen_device(&self, seen: &Seen) -> Result<(), DbError> {
        self.connection
            .execute(
                "INSERT INTO devices_seen \
                     (device_id, display_name, platform, first_seen_ms, last_seen_ms, source) \
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5) \
                 ON CONFLICT (device_id) DO UPDATE SET \
                     display_name = ?2, \
                     platform = ?3, \
                     -- ★ Never moved forward. A device that was seen six months ago and is seen again has been seen
                     -- continuously in the sense that matters, and the first sighting is the fact a user wants.
                     last_seen_ms = MAX(last_seen_ms, ?4), \
                     source = ?5",
                params![
                    seen.device_id.as_str(),
                    seen.display_name.as_str(),
                    seen.platform.as_str(),
                    seen.seen_at_ms,
                    seen.source.as_str()
                ],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Every paired device, ordered by name so two runs agree.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`], or [`DbError::Row`] for a row the schema should not have allowed.
    pub fn paired_devices(&self) -> Result<Vec<DeviceRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM paired_devices ORDER BY display_name, device_id",
            crate::records::columns::DEVICE.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(DeviceRow::from_columns(
                    crate::records::DeviceText {
                        device_id: row.get::<_, Option<String>>(0)?.as_deref(),
                        display_name: row.get::<_, Option<String>>(1)?.as_deref(),
                        platform: row.get::<_, Option<String>>(2)?.as_deref(),
                        features: row.get::<_, Option<String>>(3)?.as_deref(),
                        address: row.get::<_, Option<String>>(7)?.as_deref(),
                    },
                    crate::records::DeviceNumbers {
                        paired_at_ms: row.get::<_, Option<i64>>(4)?,
                        last_seen_ms: row.get::<_, Option<i64>>(5)?,
                        blocked: row.get::<_, Option<i64>>(6)?,
                    },
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<DeviceRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<DeviceRow>, RowError>>().map_err(DbError::from)
    }

    /// Every device the kernel has merely heard from.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn seen_devices(&self) -> Result<Vec<SeenDeviceRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM devices_seen ORDER BY last_seen_ms DESC, device_id",
            crate::records::columns::SEEN_DEVICE.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(SeenDeviceRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?.as_deref(),
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<SeenDeviceRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<SeenDeviceRow>, RowError>>().map_err(DbError::from)
    }
}
