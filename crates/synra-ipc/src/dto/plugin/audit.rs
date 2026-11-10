use serde::{Deserialize, Serialize};

/// One entry from a plugin's audit trail.
///
/// There is deliberately no content field: the design document forbids payloads in an audit record, and the
/// absence of a field is what enforces it rather than a rule someone has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntryDto {
    /// When it happened.
    pub at_ms: i64,
    /// What was attempted.
    pub capability: String,
    /// Whether it was allowed.
    pub allowed: bool,
    /// Why not, when it was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How long the call took.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    /// The trace it belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}
