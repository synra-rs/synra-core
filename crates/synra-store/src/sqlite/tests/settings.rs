use super::super::ConfigChange;
use super::migrated;

#[test]
fn a_setting_written_as_a_string_reads_back_as_a_string_not_as_text() {
    // ★ The reason `set_config` serialises rather than taking text.
    //
    // The column holds JSON text, so a caller who wrote `value.to_string()` would store `Study PC` — which parses as
    // nothing at all, and fails much later in a settings screen rather than here.
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 7).expect("writes");

    let entry = db.config().expect("reads").remove(0);
    assert_eq!(entry.key, "ui.locale");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&entry.value).expect("parses"),
        serde_json::json!("zh")
    );
}

#[test]
fn writing_a_setting_twice_is_one_key_and_the_second_wins() {
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 7).expect("first");
    db.set_config("ui.locale", &serde_json::json!("en"), 9).expect("second");

    let all = db.config().expect("reads");
    assert_eq!(all.len(), 1, "a key is a key");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&all[0].value).expect("parses"),
        serde_json::json!("en"),
        "and the later write is the one that stands"
    );
    assert_eq!(all[0].updated_ms, 9, "with the time it was written");
}

#[test]
fn a_setting_of_every_json_shape_round_trips() {
    // A configuration screen edits numbers, booleans, lists and objects — a writer that only handled strings would be
    // useless for all four, so each is checked rather than assuming.
    let db = migrated();
    let cases = [
        ("a.number", serde_json::json!(42)),
        ("a.fraction", serde_json::json!(-0.5)),
        ("a.boolean", serde_json::json!(true)),
        ("a.list", serde_json::json!(["x", "y"])),
        ("an.object", serde_json::json!({"k": "v"})),
        ("a.null", serde_json::Value::Null),
    ];
    for (key, value) in &cases {
        db.set_config(key, value, 1).expect("writes");
    }

    let all = db.config().expect("reads");
    assert_eq!(all.len(), cases.len());
    for (key, value) in &cases {
        let row = all.iter().find(|row| row.key == *key).expect("the row is there");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&row.value).expect("parses"),
            *value,
            "{key} came back as something else"
        );
    }
}

#[test]
fn removing_a_setting_reports_whether_there_was_one() {
    // ★ Why the count is returned at all.
    //
    // A `DELETE` that matches nothing reports success. A command that answered "done" for a key the user had already
    // removed would be indistinguishable from one that actually removed it.
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 1).expect("writes");

    assert!(db.unset_config("ui.locale").expect("removes"), "it was there");
    assert!(db.config().expect("reads").is_empty());
    assert!(!db.unset_config("ui.locale").expect("removes"), "the second time it was not");
}

#[test]
fn a_batch_writes_every_key_it_was_given() {
    let db = migrated();
    db.apply_config(
        &[
            ConfigChange { key: "ui.locale".to_owned(), value: Some(serde_json::json!("zh")) },
            ConfigChange { key: "sync.enabled".to_owned(), value: Some(serde_json::json!(false)) },
        ],
        11,
    )
    .expect("applies");

    let all = db.config().expect("reads");
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|row| row.updated_ms == 11), "one clock, not two");
}

#[test]
fn a_batch_can_set_and_remove_at_the_same_time() {
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 1).expect("writes");
    db.set_config("ui.theme", &serde_json::json!("dark"), 1).expect("writes");

    db.apply_config(
        &[
            ConfigChange { key: "ui.locale".to_owned(), value: Some(serde_json::json!("en")) },
            ConfigChange { key: "ui.theme".to_owned(), value: None },
        ],
        12,
    )
    .expect("applies");

    let all = db.config().expect("reads");
    assert_eq!(all.len(), 1, "the theme is gone");
    assert_eq!(all[0].key, "ui.locale", "and the locale was replaced, not merely added");
}

#[test]
fn an_empty_batch_changes_nothing_and_is_not_an_error() {
    // A settings screen that renders before the user has touched anything will send this, and answering it with an error
    // would make the screen look broken on open.
    let db = migrated();
    db.set_config("ui.locale", &serde_json::json!("zh"), 1).expect("writes");
    db.apply_config(&[], 99).expect("applies");

    assert_eq!(db.config().expect("reads").len(), 1);
    assert_eq!(db.config().expect("reads").remove(0).updated_ms, 1, "and it was not rewritten");
}

#[test]
fn a_config_value_round_trips_as_json() {
    let db = migrated();
    db.connection
        .execute(
            "INSERT INTO config (key, value, updated_ms) VALUES ('ui.locale', '\"zh\"', 7)",
            [],
        )
        .expect("a setting");

    let entry = db.config().expect("reads").remove(0);
    assert_eq!(entry.key, "ui.locale");
    assert_eq!(entry.json().expect("json"), serde_json::json!("zh"));
}
