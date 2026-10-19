//! Transfers, as rows and as the requests that start one.

use serde::{Deserialize, Serialize};

use synra_protocol::{DeviceId, TransferId};

// ─────────────────────────────────────────────────────────────────────────────
// Transfers
// ─────────────────────────────────────────────────────────────────────────────

/// A file that has landed in this device's inbox.
///
/// This is the history the in-flight list cannot be: `TransferFinished` removes the row, and the file stays. It is read
/// from the inbox rather than from a table because the inbox is where the file actually is — a row that outlived the file
/// would send a user to a path that no longer exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedFile {
    /// Its name, as it landed.
    pub file_name: String,
    /// Where it landed, so the user can open it.
    pub path: String,
    /// How large it is.
    pub bytes: u64,
    /// When it was last written, in milliseconds since the epoch.
    pub received_at_ms: i64,
}

/// A transfer, as a row in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSnapshot {
    /// The transfer.
    pub transfer_id: TransferId,
    /// The other device.
    pub peer_device: DeviceId,
    /// The peer's name, so the row does not need a second lookup.
    pub peer_name: String,
    /// `send` or `receive`.
    pub direction: String,
    /// `plugin-bundle` or `attachment`.
    pub kind: String,
    /// Where it is in its life. `snake_case`.
    pub state: String,
    /// The file's name, sanitised for display.
    pub file_name: String,
    /// How many bytes have moved.
    pub received_bytes: u64,
    /// How many there are in total.
    pub total_bytes: u64,
    /// How many blocks are done, for a resumable transfer.
    pub blocks_done: u32,
    /// How many there are.
    pub blocks_total: u32,
    /// Why it stopped, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
    /// When it started, in milliseconds since the epoch.
    pub started_at_ms: i64,
}

impl TransferSnapshot {
    /// How far along it is, from `0` to `1`.
    ///
    /// A total of zero gives `0` rather than `NaN`, because a `NaN` in a progress bar is a bar that renders at
    /// whatever width the platform's arithmetic produces.
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        // Clamped because a resumed transfer can report more received than the total it was created with — the
        // file changed size on the sender. A progress of `1.4` would render outside its bar.
        (self.received_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
    }
}

/// The compact form a device card carries.
///
/// Not `Eq`: `progress` is a fraction, and a fraction has no total equality — so `PartialEq` is the strongest
/// thing this can implement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSummary {
    /// The transfer.
    pub transfer_id: TransferId,
    /// `send` or `receive`.
    pub direction: String,
    /// How far along, from `0` to `1`.
    pub progress: f64,
}

/// A file to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileRequest {
    /// Where it goes.
    pub to: DeviceId,
    /// The path, as the interface received it.
    pub path: String,
    /// An opaque identifier grouping this file with a conversation or an intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

/// Text to send as a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTextRequest {
    /// Where it goes.
    pub to: DeviceId,
    /// The text.
    pub text: String,
    /// What to call the file it becomes.
    pub file_name: String,
    /// An opaque identifier grouping it with a conversation or an intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}
