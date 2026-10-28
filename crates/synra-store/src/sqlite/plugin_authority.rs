//! One durable authority snapshot, independent of timestamps and runtime instance state.

use super::{DbError, SynraDb};
use rusqlite::{OptionalExtension as _, params};

/// Facts a UI session was admitted against; any authority mutation changes its revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginAuthority {
    /// Globally increasing allocation, never reused by deleting and reinstalling a plugin.
    pub revision: i64,
    /// Whether the user enabled the plugin.
    pub enabled: bool,
    /// Whether the user confirmed its capabilities.
    pub trusted: bool,
}

impl PluginAuthority {
    /// Whether these persistent decisions permit a page to start.
    #[must_use]
    pub const fn permits_ui(self) -> bool {
        self.enabled && self.trusted
    }
}

/// Consistent grants and authority from one SQLite read snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginUiSnapshot {
    /// The persistent eligibility and revision.
    pub authority: PluginAuthority,
    /// The decisions committed in that revision.
    pub grants: Vec<crate::PluginGrantRow>,
}

impl SynraDb {
    /// Reads UI eligibility and grants without mixing commits from another connection.
    ///
    /// # Errors
    /// [`DbError::Statement`] if the read transaction cannot complete.
    pub fn plugin_ui_snapshot(&self, plugin_id: &str) -> Result<Option<PluginUiSnapshot>, DbError> {
        let transaction =
            self.connection
                .unchecked_transaction()
                .map_err(|error| DbError::Statement {
                    why: error.to_string(),
                })?;
        let snapshot = self
            .plugin_authority(plugin_id)?
            .map(|authority| {
                self.plugin_grants(plugin_id)
                    .map(|grants| PluginUiSnapshot { authority, grants })
            })
            .transpose()?;
        transaction.commit().map_err(|error| DbError::Statement {
            why: error.to_string(),
        })?;
        Ok(snapshot)
    }
    /// Reads the current page authority in one query; absence never authorizes a page.
    ///
    /// # Errors
    /// [`DbError::Statement`] if authority cannot be read.
    pub fn plugin_authority(&self, plugin_id: &str) -> Result<Option<PluginAuthority>, DbError> {
        self.connection
            .query_row(
                "SELECT authority_revision, enabled, trusted FROM plugins WHERE plugin_id = ?1",
                params![plugin_id],
                |row| {
                    Ok(PluginAuthority {
                        revision: row.get(0)?,
                        enabled: row.get(1)?,
                        trusted: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|error| DbError::Statement {
                why: error.to_string(),
            })
    }

    /// Invalidates pages before an explicit reload, including a reload of the same version.
    ///
    /// # Errors
    /// [`DbError::Statement`] if the transaction cannot commit; neither revision changes on failure.
    pub fn invalidate_plugin_authority(&self, plugin_id: &str) -> Result<bool, DbError> {
        let write = || -> rusqlite::Result<bool> {
            let transaction = self.connection.unchecked_transaction()?;
            transaction.execute(
                "UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1",
                [],
            )?;
            let changed = transaction.execute(
                "UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1) WHERE plugin_id = ?1",
                params![plugin_id],
            )?;
            transaction.commit()?;
            Ok(changed != 0)
        };
        write().map_err(|error| DbError::Statement {
            why: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests;
