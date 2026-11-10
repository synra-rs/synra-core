//! Synchronisation history and current-state rows.

use serde::{Deserialize, Serialize};

use super::{required, RowError};

/// One round of sync, as `sync_log` keeps it — a row of **history**, not of state.
///
/// ★ **The shape is `intents`' (migration v9), and for the reason written there**: the document is the row, and the
/// columns beside it are the projection a query needs without parsing every row. So `document` carries whatever the kernel
/// serialises a round as, and this type deliberately does not know what that is — `synra-store` depends on
/// `synra-protocol` and not on the crate that owns [`crate::records::SyncRow`]'s counterpart for a single round.
///
/// The difference from [`SyncRow`] is the whole point of having two tables: that one is replaced on every round and
/// answers "does the peer already have it"; this one is appended to and answers "what happened, and when".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncLogRow {
    /// The round's identifier.
    pub sync_id: String,
    /// Which plugin.
    pub plugin_id: String,
    /// Which peer device.
    pub peer_device: String,
    /// When it started.
    pub started_at_ms: i64,
    /// When it finished, still `None` while it is running.
    pub finished_at_ms: Option<i64>,
    /// The kernel's own serialisation of the round.
    pub document: String,
}

impl SyncLogRow {
    /// Builds a row from the columns a query selects, in `columns::SYNC_LOG` order.
    ///
    /// # Errors
    ///
    /// [`RowError`] naming the column that was NULL.
    pub fn from_columns(
        sync_id: Option<&str>,
        plugin_id: Option<&str>,
        peer_device: Option<&str>,
        started_at_ms: Option<i64>,
        finished_at_ms: Option<i64>,
        document: Option<&str>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            sync_id: required(sync_id, "sync_id")?.to_owned(),
            plugin_id: required(plugin_id, "plugin_id")?.to_owned(),
            peer_device: required(peer_device, "peer_device")?.to_owned(),
            started_at_ms: required(started_at_ms, "started_at_ms")?,
            // Not `required`: a round that has not finished has no finish time, and that is a fact rather than a defect.
            finished_at_ms,
            document: required(document, "document")?.to_owned(),
        })
    }
}

/// What one device holds for one plugin — a row of `sync_records`.
///
/// ★ **This is not the same thing as [`crate::plugin_sync::SyncRecord`]**, and the two names being alike is a trap worth
/// naming: that type is a **log line** (one per round, with a verdict, a byte count and a trace), and this is
/// **current state** (one per device, replaced on each round). This one answers "does the peer already have it", which is
/// the question that decides whether to send the package at all.
///
/// ★ **2026-10-18: the table has writers now** — a received bundle records it, a sent bundle records what the receiver
/// answered, and a sync plan records what each peer said it holds. Before that it was created by the first migration and
/// written by nothing, so a restart made every device look like it had nothing: the duplicate transfer the design's third
/// step exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRow {
    /// Which plugin.
    pub plugin_id: String,
    /// Which peer device.
    pub peer_device: String,
    /// The version it holds.
    pub version: String,
    /// The digest of the artifact it holds.
    pub digest: String,
    /// When this was recorded.
    pub synced_at_ms: i64,
}

impl SyncRow {
    /// Builds a row from the columns a query selects, in `columns::SYNC` order.
    ///
    /// # Errors
    ///
    /// [`RowError`] naming the column that was NULL.
    pub fn from_columns(
        plugin_id: Option<&str>,
        peer_device: Option<&str>,
        version: Option<&str>,
        digest: Option<&str>,
        synced_at_ms: Option<i64>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            plugin_id: required(plugin_id, "plugin_id")?.to_owned(),
            peer_device: required(peer_device, "peer_device")?.to_owned(),
            version: required(version, "version")?.to_owned(),
            digest: required(digest, "digest")?.to_owned(),
            synced_at_ms: required(synced_at_ms, "synced_at_ms")?,
        })
    }
}


