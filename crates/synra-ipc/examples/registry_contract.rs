//! Serialize actual configuration decisions and registry workflow errors for frontend conformance.

use synra_ipc::{IpcError, RegistryProblem};
use synra_protocol::{ErrorCode, error::SuggestedAction};
use synra_registry::RegistryConfig;

fn main() -> Result<(), serde_json::Error> {
    let inputs = [
        None,
        Some(serde_json::json!("")),
        Some(serde_json::json!([])),
        Some(serde_json::json!(123)),
        Some(serde_json::json!({"url": "https://registry.example"})),
        Some(serde_json::json!([123, "https://registry.example"])),
        Some(serde_json::json!(["https://registry.example", ""])),
        Some(serde_json::json!("https://host:bad")),
        Some(serde_json::json!("http://registry.example")),
        Some(serde_json::json!("https://user:secret@registry.example")),
        Some(serde_json::json!("https://registry.example?token=secret")),
        Some(serde_json::json!("https://registry.example/prefix")),
        Some(serde_json::json!("static:https://bucket.example/plugins/")),
        Some(serde_json::json!([
            "HTTPS://Registry.Example:443/",
            "http://[::1]:4123/"
        ])),
    ];
    let settings: Vec<_> = inputs
        .into_iter()
        .map(|value| {
            let outcome = match RegistryConfig::parse(value.as_ref()) {
                Ok(config) if config.sources().is_empty() => serde_json::json!({
                    "error": RegistryProblem::NotConfigured.into_error(),
                }),
                Ok(config) => serde_json::json!({
                    "sources": config.sources().iter().map(|source| serde_json::json!({
                        "url": source.url(), "host": source.host(), "secure": source.secure(),
                        "kind": source.kind(),
                    })).collect::<Vec<_>>(),
                }),
                Err(error) => serde_json::json!({
                    "error": RegistryProblem::InvalidConfiguration {
                        field: "plugins.registry".to_owned(), index: error.index,
                        reason: error.reason.to_string(),
                    }.into_error(),
                }),
            };
            serde_json::json!({"present": value.is_some(), "value": value, "outcome": outcome})
        })
        .collect();
    let contract = serde_json::json!({
        "notConfigured": RegistryProblem::NotConfigured.into_error(),
        "invalidConfiguration": RegistryProblem::InvalidConfiguration {
            field: "plugins.registry".to_owned(), index: Some(1),
            reason: "every mirror must be a nonempty URL string".to_owned(),
        }.into_error(),
        "searchUnsupported": RegistryProblem::SearchUnsupported.into_error(),
        "network": IpcError::unknown(ErrorCode::Timeout).with_action(SuggestedAction::Retry),
        "settings": settings,
    });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &contract)
}
