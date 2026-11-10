use serde_json::json;
use super::super::{Config, ConfigError};
use super::{catalog, key};

#[test]
fn a_file_round_trips_through_the_text() {
    let mut config = Config::new(catalog());
    config
        .apply(
            &[(key("ui.locale"), json!("zh")), (key("companion.showAvatar"), json!(false))],
            &[],
        )
        .expect("apply");

    let text = config.to_json().expect("serialise");
    let mut reloaded = Config::new(catalog());
    assert_eq!(reloaded.load_json(&text).expect("load"), 2);
    assert_eq!(reloaded.get(&key("ui.locale")), Some(&json!("zh")));
    assert_eq!(reloaded.get(&key("companion.showAvatar")), Some(&json!(false)));
}

#[test]
fn a_file_keeps_a_key_this_build_does_not_know() {
    // ★ Dropping it would make opening a config in an older build lose settings — and an interface's own setting is
    // exactly one this build does not know.
    let mut config = Config::new(catalog());
    config
        .load_json(r#"{"companion.showAvatar": true, "future.setting": [1, 2]}"#)
        .expect("load");

    let values = config.values();
    assert_eq!(values["companion.showAvatar"], json!(true));
    assert_eq!(values["future.setting"], json!([1, 2]));
    assert_eq!(config.override_count(), 2);
}

#[test]
fn a_value_the_catalogue_refuses_stops_the_whole_file() {
    // ★ Keeping it would mean a screen rendering a value the kernel cannot use, and the user seeing a setting that
    // appears set and has no effect.
    let mut config = Config::new(catalog());
    let result = config.load_json(r#"{"ui.locale": "zh", "transfer.resume": "yes"}"#);
    assert!(result.is_err(), "{result:?}");
    // The good key was not written either — the same all-or-nothing rule as a patch.
    assert!(config.is_default());
}

#[test]
fn a_file_that_is_not_json_is_refused_rather_than_treated_as_empty() {
    // ★ An empty configuration is indistinguishable from "the user wants everything at its default", so a file that
    // failed to parse would silently reset every setting the user had chosen.
    let mut config = Config::new(catalog());
    assert!(matches!(
        config.load_json("{ not json"),
        Err(ConfigError::Unreadable { .. })
    ));
    assert!(config.is_default());
}

#[test]
fn a_file_whose_top_level_is_not_an_object_is_refused() {
    // A list or a string at the top level is a file that something else wrote, and reading it as settings would
    // produce one key named after the whole document.
    let mut config = Config::new(catalog());
    for text in ["[1, 2]", "\"text\"", "42", "null"] {
        match config.load_json(text) {
            Err(ConfigError::NotAnObject { found }) => assert!(!found.is_empty(), "{text}"),
            other => panic!("`{text}` was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_file_with_a_malformed_key_is_refused() {
    // The same rule as a patch: a second key for the same setting is one no screen reads.
    let mut config = Config::new(catalog());
    assert!(matches!(
        config.load_json(r#"{"transfer..maxConcurrent": 3}"#),
        Err(ConfigError::BadKey { .. })
    ));
}

#[test]
fn an_empty_file_is_a_configuration_at_its_defaults() {
    // `{}` is a legitimate file: a user who has chosen nothing.
    let mut config = Config::new(catalog());
    assert_eq!(config.load_json("{}").expect("load"), 0);
    assert!(config.is_default());
    assert_eq!(config.get(&key("ui.locale")), Some(&json!("en")));
}

#[test]
fn the_written_file_holds_only_the_overrides() {
    // ★ Not the defaults. A file that wrote every default would turn "the user has chosen nothing" into "the user
    // has chosen every value", so a default changed in a later version would never reach an existing user.
    let mut config = Config::new(catalog());
    config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply");

    let text = config.to_json().expect("serialise");
    assert!(text.contains("ui.locale"), "{text}");
    assert!(!text.contains("transfer.maxConcurrent"), "{text}");
    assert!(!text.contains("transfer.resume"), "{text}");
    // And it ends with a newline, because a file a person may edit should not be a diff waiting to happen.
    assert!(text.ends_with('\n'), "{text:?}");
}

#[test]
fn loading_a_file_replaces_the_previous_overrides_for_its_keys() {
    // A file is the whole of what the user chose, so a key it carries wins over what was loaded before.
    let mut config = Config::new(catalog());
    config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply");
    config.load_json(r#"{"ui.locale": "fr"}"#).expect("load");
    assert_eq!(config.get(&key("ui.locale")), Some(&json!("fr")));
    assert_eq!(config.override_count(), 1);
}
