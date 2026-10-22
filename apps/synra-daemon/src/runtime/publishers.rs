//! Publisher trust decisions made through the local control socket.

use super::Runtime;
use synra_control::{Kernel as _, Refusal};
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
    if row.trust == synra_store::TRUST_REVOKED {
        // ★ A revocation is about the code already installed, not only the next download. v1 keeps one key per
        // publisher, so the manifest's publisher id names the same set the signature would; key rotation is not
        // implemented.
        stop_publisher_plugins(runtime, &row.publisher_id);
    }
    Ok(serde_json::json!({"publisher":value(&row)}))
}

/// Disables and unloads every installed plugin the revoked publisher signed.
///
/// Failures are logged rather than returned: the decision is recorded, and an error would tell the caller the revocation
/// did not happen. A plugin that could not be stopped keeps `enabled = 0`, so the next start does not bring it back.
fn stop_publisher_plugins(runtime: &Runtime, publisher_id: &str) {
    let Ok(rows) = runtime.db().plugins() else {
        return;
    };
    for row in rows {
        if !row.enabled && !row.trusted {
            continue;
        }
        let manifest = std::fs::read_to_string(runtime.paths.plugin_dir(&row.plugin_id).join("manifest.json"))
            .ok()
            .and_then(|text| synra_plugin_api::Manifest::from_json(&text).ok());
        if !manifest.is_some_and(|manifest| manifest.publisher.id == publisher_id) {
            continue;
        }
        let _ = runtime.db().set_plugin_trusted(&row.plugin_id, false, synra_store::sqlite::now_ms());
        if let Err(error) = runtime.plugin_set_enabled(&row.plugin_id, false) {
            eprintln!("synra-daemon: the revoked plugin {} could not be stopped: {error}", row.plugin_id);
        }
    }
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
