//! Configuration rows.

use serde::{Deserialize, Serialize};

use super::{required, RowError};

/// One setting, as the `config` table holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRow {
    /// The dotted path.
    pub key: String,
    /// The value, as JSON text.
    pub value: String,
    /// When it was written.
    pub updated_ms: i64,
}

impl ConfigRow {
    /// Builds a row from the columns `config` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        key: Option<&str>,
        value: Option<&str>,
        updated_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            key: required(key, "key")?.to_owned(),
            value: required(value, "value")?.to_owned(),
            updated_ms: required(updated_ms, "updated_ms")?,
        })
    }

    /// The value as JSON.
    ///
    /// # Errors
    ///
    /// [`RowError::WrongType`] when the text is not JSON. A refusal rather than a fallback to the raw string, because a
    /// caller that received a string where it expected a value would write it back as a doubly-encoded one.
    pub fn json(&self) -> Result<serde_json::Value, RowError> {
        serde_json::from_str(&self.value).map_err(|error| RowError::WrongType {
            column: "value",
            wanted: "JSON",
            found: format!("{error}"),
        })
    }
}


