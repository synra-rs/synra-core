//! Human-readable publisher fingerprints and trust decisions.

use serde_json::Value;

pub(super) fn render(value: &Value) -> Option<Vec<String>> {
    if let Some(publisher) = value.get("publisher") {
        return Some(vec![line(publisher)]);
    }
    let publishers = value.get("publishers")?.as_array()?;
    Some(if publishers.is_empty() {
        vec!["no publisher signatures recorded".to_owned()]
    } else {
        publishers.iter().map(line).collect()
    })
}

fn line(value: &Value) -> String {
    let id = value
        .get("publisherId")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let fingerprint = value
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let trust = value.get("trust").and_then(Value::as_str).unwrap_or("?");
    format!("{id}  {fingerprint}  {trust}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Shape, outcome_of};

    #[test]
    fn both_output_formats_preserve_the_key_a_person_must_confirm() {
        let row = serde_json::json!({"publisherId":"@acme","fingerprint":"AB12 CD34 EF56 7890","trust":"seen"});
        for value in [
            serde_json::json!({"publishers":[row]}),
            serde_json::json!({"publisher":row}),
        ] {
            let response = synra_control::Response::ok(value.clone());
            let prose = outcome_of(&response, Shape::Prose).text();
            assert!(prose.contains("@acme  AB12 CD34 EF56 7890  seen"));
            let json: Value =
                serde_json::from_str(&outcome_of(&response, Shape::Json).text()).expect("json");
            assert_eq!(json, value);
        }
        assert_eq!(
            render(&serde_json::json!({"publishers":[]})).expect("empty"),
            ["no publisher signatures recorded"]
        );
    }
}
