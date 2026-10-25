//! Explicit local commands for the restricted first-pairing workflow.

use serde::{Deserialize, Serialize};
use synra_protocol::RequestId;

/// One human-authorized action; invitation imports must come from a trusted out-of-band path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum PairingAction {
    /// Export this device's public certificate invitation.
    Invite,
    /// Approve an initiator invitation and return the temporary responder invitation.
    Listen {
        /// Intended peer id or unambiguous discovery name.
        device: String,
        /// Public invitation obtained from that device through a trusted path.
        invitation: String,
    },
    /// Approve the responder invitation and start restricted mutual confirmation.
    Connect {
        /// Intended peer id or unambiguous discovery name.
        device: String,
        /// Responder invitation returned through a trusted path.
        reply: String,
    },
    /// Read the current or most recent bounded operation.
    Status,
    /// Cancel exactly one local task generation before authorization commits.
    Cancel {
        /// The task returned by Listen or Connect.
        request_id: RequestId,
    },
}
