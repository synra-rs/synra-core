use super::*;

impl SynraDb {
    /// Records an action a plugin declares, replacing an earlier declaration under the same name.
    ///
    /// # Why this is an upsert
    ///
    /// Because a plugin declares its actions each time it activates, and the second declaration of the same name is the
    /// same action with a possibly newer schema — not a conflict. Refusing it would make the declaration path work once
    /// and fail on every restart.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the row is refused. For a well-formed call the one ordinary cause is that the plugin
    /// is not installed: `plugin_actions` references `plugins`, so an action cannot outlive the plugin that declared it.
    pub fn record_plugin_action(
        &self,
        plugin_id: &str,
        name: &str,
        args_schema: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), DbError> {
        timed_write!(self, "plugin", {
            self.connection
                .execute(
                    "INSERT INTO plugin_actions (plugin_id, name, args_schema, description) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT(plugin_id, name) DO UPDATE SET \
                        args_schema = excluded.args_schema, \
                        description = excluded.description",
                    params![plugin_id, name, args_schema, description],
                )
                .map_err(|error| DbError::Statement { why: error.to_string() })?;
            Ok(())
        })
    }

    /// The actions a plugin has declared, ordered by name.
    ///
    /// Sorted for the same reason [`SynraDb::plugins`] is: an interface that renders buttons from this list should draw
    /// them in the same order on two reads, and a table's natural order is not that.
    ///
    /// # Errors
    ///
    /// [`DbError::Statement`] when the rows cannot be read.
    pub fn plugin_actions(&self, plugin_id: &str) -> Result<Vec<PluginActionRow>, DbError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT name, args_schema, description FROM plugin_actions \
                 WHERE plugin_id = ?1 ORDER BY name",
            )
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        let rows = statement
            .query_map(params![plugin_id], |row| {
                Ok(PluginActionRow {
                    name: row.get(0)?,
                    args_schema: row.get(1)?,
                    description: row.get(2)?,
                })
            })
            .map_err(|error| DbError::Statement { why: error.to_string() })?
            .collect::<Result<Vec<PluginActionRow>, _>>()
            .map_err(|error| DbError::Statement { why: error.to_string() })?;
        Ok(rows)
    }
}
