use super::super::{ConfigError, SettingKey};
use super::key;

#[test]
fn a_key_is_a_dotted_path() {
    let parsed = key("transfer.maxConcurrent");
    assert_eq!(parsed.as_str(), "transfer.maxConcurrent");
    assert_eq!(parsed.name(), "maxConcurrent");
    assert_eq!(parsed.group(), Some("transfer"));
    assert_eq!(key("darkMode").name(), "darkMode");
}

#[test]
fn a_top_level_key_has_no_group_rather_than_an_empty_one() {
    // `None` and `Some("")` are different: a setting with no group and one in a group named by the empty string are
    // not the same thing, and only one of them is representable.
    assert_eq!(key("darkMode").group(), None);
}

#[test]
fn a_malformed_key_is_refused_with_the_rule_it_broke() {
    // ★ The failure a malformed key produces is silent: a patch that writes `transfer..maxConcurrent` creates a
    // second key that no screen reads, and the setting the user changed stays at its default while the config file
    // grows a line nobody can explain.
    for (text, expected) in [
        ("", "empty"),
        (".leading", "starts or ends"),
        ("trailing.", "starts or ends"),
        ("two..dots", "empty segment"),
        ("has space", "whitespace"),
    ] {
        match SettingKey::parse(text) {
            Err(ConfigError::BadKey { why, .. }) => {
                assert!(why.contains(expected), "`{text}` gave `{why}`");
            }
            other => panic!("`{text}` was accepted: {other:?}"),
        }
    }
}

#[test]
fn a_single_segment_key_is_allowed() {
    // The bag is open, and an interface's own top-level setting is not a mistake.
    assert!(SettingKey::parse("darkMode").is_ok());
    assert!(SettingKey::parse("a.b.c.d").is_ok());
}

#[test]
fn a_key_parses_through_from_str() {
    // So a caller can write `let key: SettingKey = text.parse()?` and get the same validation.
    let parsed: SettingKey = "ui.locale".parse().expect("a valid key");
    assert_eq!(parsed, key("ui.locale"));
    assert!("ui..locale".parse::<SettingKey>().is_err());
}
