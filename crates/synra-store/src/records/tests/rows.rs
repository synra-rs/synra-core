use super::super::{ConfigRow, IdentityRow, PluginRow, RowError};

#[test]
fn an_identity_row_is_built_from_its_columns() {
    let row = IdentityRow::from_columns(Some("self"), Some("This machine"), Some("linux"), Some(5))
        .expect("a row");
    assert_eq!(row.display_name, "This machine");
    assert_eq!(row.created_at_ms, 5);
}

#[test]
fn a_plugin_row_is_built_from_its_columns() {
    let row = PluginRow::from_columns(
        Some("@acme/hello"),
        Some(1),
        Some(1),
        Some("healthy"),
        Some(100),
        Some(200),
    )
    .expect("a row");
    assert_eq!(row.plugin_id, "@acme/hello");
    assert!(row.enabled);
    assert!(row.trusted);
    assert!(row.should_run());
}

#[test]
fn a_plugin_runs_only_when_it_is_both_enabled_and_trusted() {
    // ★ Two different questions, and collapsing them would make "turn this off for a moment" the same act as "I no
    // longer trust this". A plugin the user confirmed but switched off is not one to load, and one that is on but
    // never trusted is one whose capabilities nobody approved.
    let build = |enabled, trusted| {
        PluginRow::from_columns(
            Some("p"),
            Some(enabled),
            Some(trusted),
            Some("unknown"),
            Some(0),
            Some(0),
        )
        .expect("a row")
    };
    assert!(build(1, 1).should_run());
    assert!(!build(0, 1).should_run(), "switched off");
    assert!(!build(1, 0).should_run(), "never trusted");
    assert!(!build(0, 0).should_run());
}

#[test]
fn a_config_row_reads_its_value_as_json() {
    let row = ConfigRow::from_columns(Some("ui.locale"), Some(r#""zh""#), Some(7)).expect("a row");
    assert_eq!(row.json().expect("json"), serde_json::json!("zh"));
    assert_eq!(row.key, "ui.locale");
    assert_eq!(row.updated_ms, 7);
}

#[test]
fn a_config_value_that_is_not_json_is_refused_rather_than_returned_as_a_string() {
    // ★ A caller that received the raw string where it expected a value would write it back as a doubly-encoded one,
    // so the mistake would compound rather than surface.
    let row = ConfigRow::from_columns(Some("k"), Some("not json"), Some(0)).expect("a row");
    match row.json() {
        Err(RowError::WrongType { column, wanted, .. }) => {
            assert_eq!(column, "value");
            assert_eq!(wanted, "JSON");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_config_value_that_is_a_json_object_round_trips() {
    // The reason the column is TEXT: a nested structure round-trips through one table, which is what the schema's
    // comment says the dotted key is for.
    let value = serde_json::json!({"nested": {"deep": [1, 2, 3]}});
    let row = ConfigRow::from_columns(Some("k"), Some(&value.to_string()), Some(0)).expect("a row");
    assert_eq!(row.json().expect("json"), value);
}

#[test]
fn every_row_error_explains_itself() {
    let errors = [
        RowError::Missing { column: "device_id" },
        RowError::WrongType {
            column: "features",
            wanted: "a JSON array of strings",
            found: "expected value".to_owned(),
        },
        RowError::NotABoolean { column: "blocked", found: "2".to_owned() },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
        assert!(!text.contains('}'), "{error:?} -> {text}");
    }
    // And each names the column, which is what makes a positional read debuggable.
    assert!(errors[0].to_string().contains("device_id"));
    assert!(errors[1].to_string().contains("features"));
    assert!(errors[2].to_string().contains("blocked"));
}
