//! Publisher trust decisions made through the local control socket.

use super::Runtime;
use synra_control::Refusal;
use synra_protocol::error::ErrorCode;

pub(super) fn list(runtime: &Runtime) -> Result<serde_json::Value, Refusal> {
    let rows = runtime
        .db()
        .publishers()
        .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
    Ok(serde_json::json!({"publishers":rows.iter().map(value).collect::<Vec<_>>()}))
}

pub(super) fn decide(
    runtime: &Runtime,
    publisher_id: &str,
    fingerprint: &str,
    trust: &str,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    let row =
        synra_core::publishers::decide(&runtime.db(), publisher_id, fingerprint, trust, now_ms)
            .map_err(|error| Refusal::new(error.code(), error.to_string()))?;
    Ok(serde_json::json!({"publisher":value(&row)}))
}

fn value(row: &synra_store::PublisherRow) -> serde_json::Value {
    serde_json::json!({
        "publisherId":row.publisher_id,
        "fingerprint":row.fingerprint,
        "trust":row.trust,
        "firstSeenMs":row.first_seen_ms,
        "decidedMs":row.decided_ms,
    })
}
