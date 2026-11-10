//! Device identity and plugin audit rows.

use serde::{Deserialize, Serialize};

use super::{required, RowError};

/// One gated call, as the `plugin_audit` table keeps it.
///
/// # Why the store carries these four and nothing else
///
/// Because they are what the table holds, and the table holds what survives a restart: which plugin, against which
/// capability, how it ended, and when. `capability` and `outcome` travel as text because the crates that define them own
/// the spellings — a store that parsed them would need a migration every time one was renamed, and the audit would be the
/// thing that broke.
///
/// ★ There is no content field, and that is the design's decision rather than an omission: a capability names a
/// destination, never what was sent to it. It is the reason this record is safe to keep for longer than a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Which plugin made the call.
    pub plugin_id: String,
    /// The capability it was checked against.
    pub capability: String,
    /// How it ended.
    pub outcome: String,
    /// When it happened.
    pub at_ms: i64,
    /// How long it took, when it ran.
    pub elapsed_ms: Option<i64>,
    /// The trace of the action that caused the call, when there was one.
    ///
    /// Stored as text rather than a typed id for the same reason `plugin_id` is: the store does not parse the protocol's
    /// identifiers, and a column it validated would need a migration every time the identifier's spelling changed.
    pub trace_id: Option<String>,
}

impl AuditRecord {
    /// Builds a row from the columns `plugin_audit` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        plugin_id: Option<&str>,
        capability: Option<&str>,
        outcome: Option<&str>,
        at_ms: Option<i64>,
        elapsed_ms: Option<i64>,
        trace_id: Option<&str>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            plugin_id: required(plugin_id, "plugin_id")?.to_owned(),
            capability: required(capability, "capability")?.to_owned(),
            outcome: required(outcome, "outcome")?.to_owned(),
            at_ms: required(at_ms, "at_ms")?,
            elapsed_ms,
            trace_id: trace_id.map(str::to_owned),
        })
    }
}

/// The device's own identity.
///
/// # Why this is a row like any other
///
/// Because the schema enforces one row with `CHECK (id = 1)`, and the kernel reads it the same way — it does not hold it
/// in memory across a run, so that a kernel and a `doctor` run see the same identity rather than one of them having
/// cached it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRow {
    /// This device's identifier.
    pub device_id: String,
    /// What this device calls itself.
    pub display_name: String,
    /// What this device is.
    pub platform: String,
    /// When the identity was created.
    pub created_at_ms: i64,
}

impl IdentityRow {
    /// Builds a row from the columns `identity` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        device_id: Option<&str>,
        display_name: Option<&str>,
        platform: Option<&str>,
        created_at_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            device_id: required(device_id, "device_id")?.to_owned(),
            display_name: required(display_name, "display_name")?.to_owned(),
            platform: required(platform, "platform")?.to_owned(),
            created_at_ms: required(created_at_ms, "created_at_ms")?,
        })
    }
}


