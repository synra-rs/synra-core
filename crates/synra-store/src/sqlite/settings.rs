use rusqlite::params;

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

    /// Writes a setting, replacing whatever was there.
    ///
    /// # Why `&self` and not `&mut self`
    ///
    /// Because a `ConfigPatch` is a handful of keys and a transaction would mean borrowing the connection mutably — which
    /// this handle cannot lend, because `SynraDb` is shared by reference across threads. Each statement is atomic on its
    /// own, and the settings screens write keys one at a time anyway.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused, and [`DbError::NotJson`] when the value is not JSON text.
    pub fn set_config(&self, key: &str, value: &serde_json::Value, now_ms: i64) -> Result<(), DbError> {
        // ★ Serialised here rather than by the caller.
        //
        // The column is JSON *text* because the table predates the settings screens and a column type cannot change under
        // a published migration. Whoever writes it must not get to choose how — a caller writing `value.to_string()` on a
        // string produces `Study PC`, which parses as nothing and is why this returns `DbError::NotJson` on the way out.
        let text = serde_json::to_string(value).map_err(|error| DbError::NotJson { why: error.to_string() })?;
        self.connection
            .execute(
                "INSERT INTO config (key, value, updated_ms) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (key) DO UPDATE SET value = ?2, updated_ms = ?3",
                params![key, text, now_ms],
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(())
    }

    /// Removes a setting, returning it to its default.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the write is refused.
    pub fn unset_config(&self, key: &str) -> Result<bool, DbError> {
        // ★ The count is returned, and callers must look at it.
        //
        // An `UPDATE` or `DELETE` that matches no row reports success. A command that removed a key the user had already
        // removed would then answer "done", which is indistinguishable from having actually done it.
        let removed = self
            .connection
            .execute("DELETE FROM config WHERE key = ?1", params![key])
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(removed > 0)
    }

    /// Writes a whole batch of changes, or reports why it could not.
    ///
    /// # Why this exists when the two above do not
    ///
    /// Because a settings screen can unset one key and set another in one gesture, and applying those one statement at a
    /// time leaves a configuration that is neither the old one nor the new one if the process dies halfway.
    ///
    /// # Why the store takes its own shape rather than the IPC one
    ///
    /// Because `synra-ipc` depends on this crate, and a dependency in the other direction would make the database unable
    /// to change a row without an interface release. The two are converted at the boundary, in the host.
    ///
    /// # Errors
    ///
    /// As [`SynraDb::set_config`], and [`DbError::Statement`] if a statement is refused.
    pub fn apply_config(&self, changes: &[ConfigChange], now_ms: i64) -> Result<(), DbError> {
        for change in changes {
            match &change.value {
                Some(value) => self.set_config(&change.key, value, now_ms)?,
                None => {
                    self.unset_config(&change.key)?;
                }
            }
        }
        Ok(())
    }
}

/// One setting to write or remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigChange {
    /// The dotted path.
    pub key: String,
    /// The new value, or `None` to return the key to its default.
    ///
    /// # Why `None` means *remove* and not *set to null*
    ///
    /// Because a configuration screen has a "reset this to the default" affordance, and the only way that can work is if
    /// "remove" is representable. Encoding it as JSON `null` would store a value that reads back as a setting whose value
    /// is null — which is a fourth thing, meaning neither the default nor anything the user chose.
    pub value: Option<serde_json::Value>,
}
