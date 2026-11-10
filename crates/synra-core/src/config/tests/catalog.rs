use serde_json::json;
use super::super::{Catalog, Config, ConfigError, Setting, SettingKind};
use super::{catalog, key};

#[test]
fn an_empty_catalogue_accepts_everything() {
    // ★ The kernel's settings are the screens' business, so this build registers none and every value lives as an
    // override. A catalogue that whitelisted would mean an interface could not add a setting without a kernel
    // release — which is the coupling this module exists to avoid.
    let mut config = Config::new(Catalog::new());
    config
        .apply(&[(key("anything.atAll"), json!({"nested": true}))], &[])
        .expect("apply");
    assert_eq!(config.get(&key("anything.atAll")), Some(&json!({"nested": true})));
}

#[test]
fn the_catalogue_is_iterable_in_key_order() {
    // A settings screen renders the rows in the catalogue's order, and two renders have to agree.
    let catalog = catalog();
    assert_eq!(catalog.len(), 4);
    assert!(!catalog.is_empty());
    let keys: Vec<&str> = catalog.iter().map(|setting| setting.key.as_str()).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted);
}

#[test]
fn registering_the_same_key_twice_replaces_it() {
    // A build that overrides a default registers again, and that is not a mistake to refuse.
    let mut catalog = Catalog::new();
    catalog.register(
        Setting::new("a.b", SettingKind::Integer, json!(1), "first").expect("setting"),
    );
    catalog.register(
        Setting::new("a.b", SettingKind::Integer, json!(2), "second").expect("setting"),
    );
    assert_eq!(catalog.len(), 1);
    assert_eq!(
        catalog.get(&key("a.b")).expect("the setting").default,
        json!(2)
    );
}

#[test]
fn a_setting_that_is_not_registered_is_not_checked() {
    // The catalogue is the kernel's knowledge and not a whitelist.
    let catalog = catalog();
    assert!(catalog.get(&key("nobody.knows")).is_none());
    assert!(catalog.check(&key("nobody.knows"), &json!({"anything": 1})).is_ok());
}

#[test]
fn a_check_names_what_it_expected_and_what_it_found() {
    // The message reaches a settings screen, which has to say which value was wrong and what it should have been.
    let catalog = catalog();
    match catalog.check(&key("transfer.maxConcurrent"), &json!("lots")) {
        Err(ConfigError::BadKey { key: reported, why }) => {
            assert_eq!(reported, "transfer.maxConcurrent");
            assert!(why.contains("integer"), "{why}");
            assert!(why.contains("string"), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        ConfigError::BadKey { key: "a..b".to_owned(), why: "it has an empty segment".to_owned() },
        ConfigError::SetAndUnset { key: "a.b".to_owned() },
        ConfigError::Unreadable { why: "expected value".to_owned() },
        ConfigError::NotAnObject { found: "a list" },
        ConfigError::Reserved { key: "a.b".to_owned(), why: "the kernel computes it" },
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
        assert!(!text.contains('}'), "{error:?} -> {text}");
    }
}

#[test]
fn a_setting_can_be_built_without_a_catalogue() {
    // The fixture's own path, asserted so a reader sees the constructor is the only way to make a well-formed one.
    let setting = Setting::new("a.b", SettingKind::Text, json!("x"), "d").expect("setting");
    assert!(!setting.reserved);
    assert!(Setting::new("a..b", SettingKind::Text, json!("x"), "d").is_err());
    assert!(setting.reserved().reserved);
}
