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
        // ★ A revocation is about the code already installed, not only the next download. The version row carries the
        // signing key (migration 16), so this is an index lookup and it names the key, not every plugin by the publisher.
        stop_signer_plugins(runtime, &row.fingerprint);
    }
    Ok(serde_json::json!({"publisher":value(&row)}))
}

/// Disables and unloads every active plugin the revoked key signed.
///
/// Failures are logged rather than returned: the decision is recorded, and an error would tell the caller the revocation
/// did not happen. A plugin that could not be stopped keeps `enabled = 0`, so the next start does not bring it back.
fn stop_signer_plugins(runtime: &Runtime, fingerprint: &str) {
    let Ok(plugins) = runtime.db().active_plugins_by_fingerprint(fingerprint) else {
        return;
    };
    for plugin_id in plugins {
        let _ = runtime.db().set_plugin_trusted(&plugin_id, false, synra_store::sqlite::now_ms());
        if let Err(error) = runtime.plugin_set_enabled(&plugin_id, false) {
            eprintln!("synra-daemon: the revoked plugin {plugin_id} could not be stopped: {error}");
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
