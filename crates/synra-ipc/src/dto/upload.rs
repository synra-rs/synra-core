//! Internal IPC for sending a plugin page's file in bounded chunks.

use serde::{Deserialize, Serialize};
use synra_protocol::TransferId;

/// Admission request for a page upload.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginUploadBegin {
    /// Canonical destination device identifier.
    pub to: String,
    /// File name to present to the receiver.
    pub file_name: String,
    /// Declared size in bytes.
    pub total_bytes: u64,
}

/// The upload and append budget reserved by the host.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginUploadOpened {
    /// Opaque upload identifier scoped to this page session.
    pub upload_id: String,
    /// Maximum decoded bytes per append.
    pub chunk_bytes: usize,
}

/// A request to append staged bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginUploadChunk {
    /// The upload to append to.
    pub upload_id: String,
    /// Absolute starting byte offset.
    pub offset: u64,
    /// Base64-encoded bytes.
    pub data: String,
}

/// The number of bytes committed to an upload.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginUploadAppend {
    /// The next accepted offset in bytes.
    pub written: u64,
    /// Declared file length in bytes.
    pub total_bytes: u64,
}

/// An upload to finish or abort.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginUploadHandle {
    /// The session-owned upload identifier.
    pub upload_id: String,
}

/// Result of an upload abort request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginUploadEnded {
    /// Whether this call closed a previously active upload.
    pub aborted: bool,
}

/// The send accepted by the worker after the file was fully staged.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginUploadSent {
    /// Transfer identifier for progress and terminal status lookups.
    pub transfer_id: TransferId,
}
