use crate::records::{ConfigRow, RowError};

use super::{DbError, SynraDb};

impl SynraDb {
    /// Every setting, ordered by key.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::paired_devices`].
    pub fn config(&self) -> Result<Vec<ConfigRow>, DbError> {
        let sql = format!(
            "SELECT {} FROM config ORDER BY key",
            crate::records::columns::CONFIG.join(", ")
        );
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map([], |row| {
                Ok(ConfigRow::from_columns(
                    row.get::<_, Option<String>>(0)?.as_deref(),
                    row.get::<_, Option<String>>(1)?.as_deref(),
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<Result<ConfigRow, RowError>>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;

        rows.into_iter().collect::<Result<Vec<ConfigRow>, RowError>>().map_err(DbError::from)
    }
}
