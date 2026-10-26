//! One error classification for local calls, remote execution and plugin UI adapters.

use synra_protocol::{ErrorCode, SynraError};

use super::CallOutcome;

/// Classify a plugin or forwarded host refusal while retaining its source diagnostics.
#[must_use]
pub fn reported_failure(code: &str, message: &str, details: Option<&str>) -> SynraError {
    let mut diagnostic = serde_json::Map::new();
    diagnostic.insert(
        "pluginCode".to_owned(),
        serde_json::Value::String(code.to_owned()),
    );
    if let Some(details) = details {
        diagnostic.insert(
            "pluginDetails".to_owned(),
            serde_json::from_str(details)
                .unwrap_or_else(|_| serde_json::Value::String(details.to_owned())),
        );
    }
    SynraError::new(classify(code), message).with_details(serde_json::Value::Object(diagnostic))
}

fn classify(code: &str) -> ErrorCode {
    match code {
        "capabilityDenied" => ErrorCode::CapabilityDenied,
        "badArgument" => ErrorCode::InvalidArgument,
        "hostNotAllowed" => ErrorCode::HostNotAllowed,
        "ipNotAllowed" => ErrorCode::IpNotAllowed,
        "schemeNotAllowed" => ErrorCode::SchemeNotAllowed,
        "redirectBlocked" => ErrorCode::RedirectBlocked,
        "responseTooLarge" => ErrorCode::ResponseTooLarge,
        "rateLimited" => ErrorCode::RateLimited,
        "unknownFunction" | "notImplemented" => ErrorCode::Unsupported,
        _ => serde_json::from_value(serde_json::Value::String(code.to_owned()))
            .unwrap_or(ErrorCode::Internal),
    }
}

impl CallOutcome {
    /// Return the payload or the same structured failure in every caller.
    ///
    /// # Errors
    /// A reported refusal retains its source code and optional details. Traps and resource failures
    /// use the protocol's plugin error categories and retain the applicable budget.
    pub fn into_result(self) -> Result<String, SynraError> {
        match self {
            Self::Ok(payload) => Ok(payload),
            Self::Failed {
                code,
                message,
                details,
            } => Err(reported_failure(&code, &message, details.as_deref())),
            Self::Timeout { after } => Err(SynraError::new(
                ErrorCode::PluginTimeout,
                "the plugin exceeded its time budget",
            )
            .with_details(serde_json::json!({"kind":"timeout","afterMs":after.as_millis()}))),
            Self::FuelExhausted { fuel } => Err(SynraError::new(
                ErrorCode::PluginTrapped,
                "the plugin exhausted its fuel",
            )
            .with_details(serde_json::json!({"kind":"fuelExhausted","fuel":fuel}))),
            Self::MemoryExceeded { limit } => Err(SynraError::new(
                ErrorCode::PluginTrapped,
                "the plugin exceeded its memory limit",
            )
            .with_details(serde_json::json!({"kind":"memoryExceeded","limit":limit}))),
            Self::Trap { detail } => Err(SynraError::new(ErrorCode::PluginTrapped, detail)
                .with_details(serde_json::json!({"kind":"trap"}))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_errors_keep_source_codes_and_optional_details_without_promoting_data() {
        for code in ErrorCode::all() {
            let error = reported_failure(code.as_str(), "message", None);
            assert_eq!(error.code, *code);
        }
        for (source, expected) in [
            ("capabilityDenied", ErrorCode::CapabilityDenied),
            ("notImplemented", ErrorCode::Unsupported),
            ("customRefusal", ErrorCode::Internal),
        ] {
            let error = reported_failure(source, "refused", Some(r#"{"code":"device_offline"}"#));
            assert_eq!(error.code, expected);
            assert_eq!(error.message, "refused");
            assert_eq!(
                error.details.as_deref(),
                Some(
                    &serde_json::json!({"pluginCode":source,"pluginDetails":{"code":"device_offline"}})
                )
            );
        }
    }

    #[test]
    fn execution_failures_are_typed_and_keep_their_budgets() {
        for (outcome, code, details) in [
            (
                CallOutcome::Timeout {
                    after: std::time::Duration::from_millis(20),
                },
                ErrorCode::PluginTimeout,
                serde_json::json!({"kind":"timeout","afterMs":20}),
            ),
            (
                CallOutcome::FuelExhausted { fuel: 100 },
                ErrorCode::PluginTrapped,
                serde_json::json!({"kind":"fuelExhausted","fuel":100}),
            ),
            (
                CallOutcome::MemoryExceeded { limit: 4096 },
                ErrorCode::PluginTrapped,
                serde_json::json!({"kind":"memoryExceeded","limit":4096}),
            ),
            (
                CallOutcome::Trap {
                    detail: "out of bounds".to_owned(),
                },
                ErrorCode::PluginTrapped,
                serde_json::json!({"kind":"trap"}),
            ),
        ] {
            let error = outcome.into_result().expect_err("failure");
            assert_eq!(error.code, code);
            assert_eq!(error.details.as_deref(), Some(&details));
        }
        assert_eq!(
            CallOutcome::Ok("null".to_owned()).into_result(),
            Ok("null".to_owned())
        );
    }
}
