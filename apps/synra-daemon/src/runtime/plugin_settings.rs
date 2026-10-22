//! Plugin settings written by the process that owns the database.

use synra_control::Refusal;
use synra_core::plugin_updates::{AUTO_UPDATE_KEY, REGISTRY_KEY};
use synra_protocol::error::ErrorCode;

use super::Runtime;

pub(super) fn registry(
    runtime: &Runtime,
    urls: Option<&[String]>,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    if let Some(urls) = urls {
        if urls.is_empty() {
            runtime.db().unset_config(REGISTRY_KEY).map_err(internal)?;
        } else {
            let value = serde_json::json!(urls);
            super::updates::validate_sources(&value.to_string()).map_err(invalid)?;
            runtime
                .db()
                .set_config(REGISTRY_KEY, &value, now_ms)
                .map_err(internal)?;
        }
    }
    let current = synra_core::plugin_updates::registry_setting(&runtime.db()).map_err(internal)?;
    let value = current
        .map(|raw| serde_json::from_str::<serde_json::Value>(&raw))
        .transpose()
        .map_err(internal)?;
    Ok(serde_json::json!({"registry":value}))
}

pub(super) fn policy(
    runtime: &Runtime,
    selected: Option<&str>,
    now_ms: i64,
) -> Result<serde_json::Value, Refusal> {
    if let Some(selected) = selected {
        if !["never", "notify-only", "auto-minor", "auto-all"].contains(&selected) {
            return Err(invalid("choose never, notify-only, auto-minor or auto-all"));
        }
        runtime
            .db()
            .set_config(AUTO_UPDATE_KEY, &serde_json::json!(selected), now_ms)
            .map_err(internal)?;
    }
    use synra_plugin_api::update::UpdatePolicy;
    let current = match synra_core::plugin_updates::configured_policy(&runtime.db()) {
        None => "never",
        Some(UpdatePolicy::AutoMinor) => "auto-minor",
        Some(UpdatePolicy::AutoAll) => "auto-all",
        Some(_) => "notify-only",
    };
    Ok(serde_json::json!({"updatePolicy":current}))
}

fn invalid(error: impl std::fmt::Display) -> Refusal {
    Refusal::new(ErrorCode::InvalidArgument, error.to_string())
}

fn internal(error: impl std::fmt::Display) -> Refusal {
    Refusal::new(ErrorCode::Internal, error.to_string())
}
