use serde_json::json;
use super::super::SettingKind;

#[test]
fn a_whole_float_is_not_an_integer() {
    // ★ `1.0` stored where an integer is expected is a value that compares unequal to `1` in some languages and
    // equal in others — exactly the ambiguity a typed setting exists to remove.
    assert!(SettingKind::Integer.matches(&json!(1)));
    assert!(!SettingKind::Integer.matches(&json!(1.0)));
    assert!(SettingKind::Number.matches(&json!(1.0)));
    assert!(SettingKind::Number.matches(&json!(1)));
}

#[test]
fn each_kind_accepts_what_it_names_and_refuses_the_rest() {
    assert!(SettingKind::Bool.matches(&json!(true)));
    assert!(!SettingKind::Bool.matches(&json!(1)));
    assert!(SettingKind::Text.matches(&json!("x")));
    assert!(!SettingKind::Text.matches(&json!(1)));
    assert!(SettingKind::Choice.matches(&json!("a")));
    assert!(SettingKind::TextList.matches(&json!(["a", "b"])));
    assert!(SettingKind::TextList.matches(&json!([])));
    // A list with one non-string is not a text list: the screen would render it as one and the value would fail
    // wherever it was used.
    assert!(!SettingKind::TextList.matches(&json!(["a", 1])));
    assert!(!SettingKind::TextList.matches(&json!("a")));
}

#[test]
fn every_kind_has_a_name_for_a_report() {
    let kinds = [
        SettingKind::Bool,
        SettingKind::Integer,
        SettingKind::Number,
        SettingKind::Text,
        SettingKind::Choice,
        SettingKind::TextList,
    ];
    let mut names: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), kinds.len(), "a kind name repeats");
    for name in names {
        assert!(!name.is_empty());
    }
}

#[test]
fn every_description_of_a_value_is_a_word() {
    use crate::config::setting::describe;

    // These reach a message, and one that contained a brace would be a debugging aid that looks like a bug.
    for value in [
        json!(null),
        json!(true),
        json!(1),
        json!(1.5),
        json!("x"),
        json!([]),
        json!({}),
    ] {
        let text = describe(&value);
        assert!(!text.is_empty());
        assert!(!text.contains('{'), "{text}");
    }
}
