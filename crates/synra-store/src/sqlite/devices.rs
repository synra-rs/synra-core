use crate::records::{DeviceRow, RowError, SeenDeviceRow};

use super::{DbError, SynraDb};

impl SynraDb {
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
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<String>>(2)?.as_deref(),
                    row.get::<_, Option<String>>(3)?.as_deref(),
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
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
