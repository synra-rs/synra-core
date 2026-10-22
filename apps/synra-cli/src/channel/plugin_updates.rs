//! Human-readable answers for explicit plugin update operations.

use serde_json::Value;

pub(super) fn render(value: &Value) -> Option<Vec<String>> {
    if let Some(registry) = value.get("registry") {
        return Some(vec![format!("registry: {registry}")]);
    }
    if let Some(policy) = value.get("updatePolicy").and_then(Value::as_str) {
        return Some(vec![format!("background updates: {policy}")]);
    }
    if value.get("updated").and_then(Value::as_bool) == Some(true) {
        let id = value.get("pluginId").and_then(Value::as_str).unwrap_or("?");
        let version = value.get("version").and_then(Value::as_str).unwrap_or("?");
        let state = if value.get("loaded").and_then(Value::as_bool) == Some(true) {
            "running"
        } else {
            "not running; check consent and activation status"
        };
        let mut lines = vec![format!("updated {id} to {version}; {state}")];
        if let Some(error) = value.get("activationError").and_then(Value::as_str) {
            lines.push(format!("  could not activate: {error}"));
        }
        if let Some(warnings) = value.get("warnings").and_then(Value::as_array) {
            lines.extend(
                warnings
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|warning| format!("  {warning}")),
            );
        }
        return Some(lines);
    }
    let checks = value.get("updateChecks")?.as_array()?;
    if checks.is_empty() {
        return Some(vec!["no installed plugins to check".to_owned()]);
    }
    Some(
        checks
            .iter()
            .map(|check| {
                let id = check.get("pluginId").and_then(Value::as_str).unwrap_or("?");
                let current = check
                    .get("currentVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("?");
                check
                    .get("availableVersion")
                    .and_then(Value::as_str)
                    .map_or_else(
                        || format!("{id} {current}: no update available"),
                        |version| format!("{id} {current} -> {version}"),
                    )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Shape, outcome_of};
    use synra_control::Response;

    #[test]
    fn a_failed_check_is_a_failing_command_with_its_cached_answer_and_error() {
        let value = serde_json::json!({"updateChecks":[{"pluginId":"@acme/hello","availableVersion":"1.1.0"}], "failures":[{"pluginId":"@acme/hello","message":"offline"}]});
        for shape in [Shape::Json, Shape::Prose] {
            let outcome = outcome_of(&Response::ok(value.clone()), shape);
            assert_eq!(outcome.exit_code(), 1);
            let report: Value = serde_json::from_str(&outcome.text()).expect("complete report");
            assert_eq!(report, value);
            let diagnostic: Value =
                serde_json::from_str(&outcome.diagnostic_text()).expect("parseable stderr JSON");
            assert_eq!(diagnostic, value);
        }
        assert_eq!(
            crate::CommandOutcome::Failed("offline".to_owned()).diagnostic_text(),
            "synra: offline"
        );
    }

    #[test]
    fn committed_but_inactive_updates_explain_their_status() {
        let value = serde_json::json!({"updated":true,"pluginId":"@acme/hello","version":"1.1.0","loaded":false,"activationError":"cannot activate","warnings":["no notifications"]});
        let lines = render(&value).expect("human report").join("\n");
        assert!(lines.contains("updated @acme/hello to 1.1.0; not running"));
        assert!(lines.contains("cannot activate"));
        assert!(lines.contains("no notifications"));
    }
}
