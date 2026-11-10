use serde_json::json;
use super::super::{Config, ConfigError};
use super::{catalog, key};

#[test]
fn a_patch_that_names_a_key_twice_is_refused() {
    // ★ A caller that named a key in both `set` and `unset` meant one of the two, and picking for them produces a
    // setting that is the opposite of what they asked for half the time.
    let mut config = Config::new(catalog());
    match config.apply(&[(key("ui.locale"), json!("zh"))], &[key("ui.locale")]) {
        Err(ConfigError::SetAndUnset { key: reported }) => assert_eq!(reported, "ui.locale"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And nothing was written.
    assert!(!config.is_overridden(&key("ui.locale")));
}

#[test]
fn a_patch_with_a_bad_value_changes_nothing_at_all() {
    // ★ A patch that wrote three keys and failed on the fourth would leave the configuration in a state no caller
    // asked for, and the caller — which received an error — has no way to know how far it got.
    let mut config = Config::new(catalog());
    let result = config.apply(
        &[
            (key("ui.locale"), json!("zh")),
            (key("transfer.maxConcurrent"), json!("lots")),
        ],
        &[],
    );

    assert!(result.is_err(), "{result:?}");
    // The good key was not written either.
    assert!(!config.is_overridden(&key("ui.locale")));
    assert!(config.is_default());
}

#[test]
fn a_patch_reports_only_the_keys_it_actually_changed() {
    // A patch that writes the value a key already has is a no-op, and reporting it as a change would make a screen
    // show a save that did nothing.
    let mut config = Config::new(catalog());
    assert_eq!(
        config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply"),
        1
    );
    assert_eq!(
        config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply"),
        0
    );
    assert_eq!(
        config.apply(&[(key("ui.locale"), json!("en"))], &[]).expect("apply"),
        1
    );
}

#[test]
fn unsetting_a_key_that_was_never_set_changes_nothing() {
    // A reset button pressed twice, and a screen that reported a change the second time would be lying.
    let mut config = Config::new(catalog());
    assert_eq!(config.apply(&[], &[key("ui.locale")]).expect("unset"), 0);
}

#[test]
fn a_reserved_setting_cannot_be_written() {
    // ★ A reserved setting is one the kernel computes, so a write would be a value the kernel overwrites at the next
    // start — the user's change appears to work and then silently does not.
    let mut config = Config::new(catalog());
    match config.apply(&[(key("internal.schemaVersion"), json!(99))], &[]) {
        Err(ConfigError::Reserved { key: reported, why }) => {
            assert_eq!(reported, "internal.schemaVersion");
            assert!(why.contains("overwritten"), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And unsetting it is allowed: removing a write nobody should have made is not a write.
    assert!(config.apply(&[], &[key("internal.schemaVersion")]).is_ok());
}
