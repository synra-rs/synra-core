//! The rows and the types they become.
//!
//! # Why this is separate from the binding
//!
//! A SQLite binding hands back `&str`, `i64` and `Option<T>` in the order the query named them. Turning that into the
//! kernel's own types is where the mistakes live — a swapped column, a `TEXT` where a `bool` was meant, a `NULL` where
//! the schema says `NOT NULL` — and **none of those need an engine to find**. So the conversion is a plain function over
//! plain values, and the binding's job is only to fetch them.
//!
//! The same reasoning the migration module gives for not carrying a C dependency: a crate whose whole job is to hold the
//! kernel's persistence contract should be checkable without a database.
//!
//! # The one rule every column follows
//!
//! **A column named `*_ms` is a wall-clock reading**, and the reason is the one the claim file learned: a monotonic
//! reading is only comparable within one process, and every one of these values is read by a process that did not write
//! it. A `last_seen_ms` written by the kernel and compared by a `doctor` run would be nonsense if either clock were
//! monotonic.
//!
//! # Why the types are not the interface DTOs
//!
//! [`DeviceRow`] is a **row**, and `synra-ipc`'s `DeviceCard` is what a screen draws. They differ where the database
//! differs from the interface: a row carries `blocked` and the pairing time, a card carries a last-seen age and whether
//! the device is reachable *now*. Making one type serve both would put a screen's presentation needs into the schema.


/// Why a row could not be turned into a type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RowError {
    /// A column the schema declares `NOT NULL` came back empty.
    #[error("`{column}` is missing, and the schema declares it NOT NULL")]
    Missing {
        /// The column's name.
        column: &'static str,
    },

    /// A column held something the type cannot represent.
    #[error("`{column}` holds {found}, which {wanted} cannot represent")]
    WrongType {
        /// The column's name.
        column: &'static str,
        /// What the type wanted.
        wanted: &'static str,
        /// What was found.
        found: String,
    },

    /// A TEXT column declared `CHECK (x IN (0, 1))` held something else.
    #[error("`{column}` holds {found}, and the schema allows only 0, 1, true or false")]
    NotABoolean {
        /// The column's name.
        column: &'static str,
        /// What was found.
        found: String,
    },
}

mod config;
mod devices;
mod identity;
mod intents;
mod plugins;
mod sync;

pub use config::ConfigRow;
pub use devices::{DeviceNumbers, DeviceRow, DeviceText, Seen, SeenDeviceRow};
pub use identity::{AuditRecord, IdentityRow};
pub use intents::{ActiveVersion, IntentRecord};
pub use plugins::{PluginActionRow, PluginGrantRow, PluginRow};
pub use sync::{SyncLogRow, SyncRow};

/// A `NOT NULL` column's value, or the error naming it.
pub(super) fn required<T>(value: Option<T>, column: &'static str) -> Result<T, RowError> {
    value.ok_or(RowError::Missing { column })
}

/// A column declared `CHECK (x IN (0, 1))`, as a boolean.
///
/// # Why a refusal rather than `!= 0`
///
/// The schema's `CHECK` is what makes this a two-valued column, and a reader that accepted any non-zero integer would
/// treat a `2` — which the schema forbids and a corrupt file can contain — as `true`. The point of checking is that a
/// value the schema does not allow is reported rather than interpreted.
pub(super) fn to_bool(value: Option<i64>, column: &'static str) -> Result<bool, RowError> {
    match required(value, column)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(RowError::NotABoolean { column, found: other.to_string() }),
    }
}

/// Parses the `features` column, which the schema declares `TEXT NOT NULL DEFAULT '[]'`.
///
/// # Errors
///
/// [`RowError::WrongType`] when the text is not a JSON array of strings.
pub(super) fn parse_features(text: &str) -> Result<Vec<String>, RowError> {
    serde_json::from_str::<Vec<String>>(text).map_err(|error| RowError::WrongType {
        column: "features",
        wanted: "a JSON array of strings",
        found: format!("{error}"),
    })
}

/// A pinned copy of the row types' column lists, for `synra-error-guard` and for a test.
///
/// # Why this exists
///
/// Every `from_columns` takes its arguments **positionally**, which is what a SQLite binding produces — and a binding
/// whose `SELECT` lists the columns in a different order produces a row whose fields are silently swapped. A swap between
/// two `TEXT` columns is the dangerous one: nothing fails, and a device's name becomes its platform.
///
/// So each query's column list is written down here, and a test asserts it is the order `from_columns` expects.
pub mod columns {
    /// The `paired_devices` columns a query must select, in the order `DeviceRow::from_columns` takes them.
    pub const DEVICE: &[&str] = &[
        "device_id",
        "display_name",
        "platform",
        "features",
        "paired_at_ms",
        "last_seen_ms",
        "blocked",
        // Last, because that is where the migration that added it put it. The read below is positional, so this list
        // and `DeviceRow::from_columns` are one order written twice — and this is the file that says which.
        "last_address",
    ];

    /// The `sync_log` columns, in the order `SyncLogRow::from_columns` takes them.
    pub const SYNC_LOG: &[&str] =
        &["sync_id", "plugin_id", "peer_device", "started_at_ms", "finished_at_ms", "document"];

    /// The `sync_records` columns, in the order `SyncRow::from_columns` takes them.
    ///
    /// The table's own order, and its primary key is `(plugin_id, peer_device)` — so this is a **current state** per
    /// device, not a log. See the note on `SyncRow`.
    pub const SYNC: &[&str] = &["plugin_id", "peer_device", "version", "digest", "synced_at_ms"];

    /// The `plugin_audit` columns, in the order `AuditRecord::from_columns` takes them.
    ///
    /// `id` is deliberately absent: it is the autogenerated identity of the row, and nothing reads it. Selecting it would
    /// be a column every reader has to skip past.
    pub const AUDIT: &[&str] =
        &["plugin_id", "capability", "outcome", "at_ms", "elapsed_ms", "trace_id"];

    /// The `intents` columns, in the order `IntentRecord::from_columns` takes them.
    pub const INTENT: &[&str] = &[
        "intent_id",
        "state",
        "created_ms",
        "updated_ms",
        "origin_device",
        "request_id",
        "document",
    ];

    /// The `devices_seen` columns, in the order `SeenDeviceRow::from_columns` takes them.
    pub const SEEN_DEVICE: &[&str] = &[
        "device_id",
        "display_name",
        "platform",
        "first_seen_ms",
        "last_seen_ms",
        "source",
    ];

    /// The `identity` columns, in the order `IdentityRow::from_columns` takes them.
    pub const IDENTITY: &[&str] = &["device_id", "display_name", "platform", "created_at_ms"];

    /// The `plugins` columns, in the order `PluginRow::from_columns` takes them.
    pub const PLUGIN: &[&str] = &[
        "plugin_id",
        "enabled",
        "trusted",
        "health",
        "installed_at_ms",
        "updated_at_ms",
    ];

    /// The `config` columns, in the order `ConfigRow::from_columns` takes them.
    pub const CONFIG: &[&str] = &["key", "value", "updated_ms"];

    /// The `plugin_grants` columns, in the order `PluginGrantRow::from_columns` takes them.
    pub const PLUGIN_GRANT: &[&str] =
        &["capability", "granted", "decided_ms", "manifest_digest"];
}

#[cfg(test)]
mod tests;
