//! Public task snapshots for the restricted first-pairing workflow.

use crate::ids::{DeviceId, RequestId};
use serde::{Deserialize, Serialize};

/// Runtime progress of one bounded first-pairing operation, not a durable authorization fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PairingPhase {
    /// Waiting for the invitation's intended peer on a temporary restricted port.
    Listening,
    /// Establishing pinned TLS with the explicitly approved peer.
    Connecting,
    /// Exchanging session-bound consent and durable receipts.
    Confirming,
    /// Cancellation won; the bounded worker is releasing its socket and task slot.
    Cancelling,
    /// The local durable grant was committed after both receipts.
    Paired,
    /// Cancellation prevented this task from committing.
    Cancelled,
    /// The total operation budget expired.
    TimedOut,
    /// Authentication, persistence or transport failed.
    Failed,
}

impl PairingPhase {
    /// Whether no live worker remains for this task.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Paired | Self::Cancelled | Self::TimedOut | Self::Failed
        )
    }
}

/// One local pairing task; a completed snapshot alone never authorizes a business request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingSnapshot {
    /// Local task generation used for polling and cancellation.
    pub request_id: RequestId,
    /// The exact device id extracted from the out-of-band approved certificate.
    pub peer_id: DeviceId,
    /// Current runtime phase.
    pub phase: PairingPhase,
    /// Absolute presentation deadline; the worker also owns a monotonic deadline.
    pub expires_at_ms: i64,
    /// Public responder invitation to return through the trusted out-of-band path.
    pub reply: Option<String>,
    /// Structured failure category, when the task failed.
    pub error_code: Option<crate::ErrorCode>,
    /// Diagnostic detail without private keys or the imported invitation.
    pub detail: Option<String>,
}
