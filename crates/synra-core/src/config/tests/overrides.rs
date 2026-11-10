use serde_json::json;
use super::super::Config;
use super::{catalog, key};

#[test]
fn a_setting_the_user_has_not_touched_reads_as_its_default() {
    let config = Config::new(catalog());
    assert_eq!(config.get(&key("transfer.maxConcurrent")), Some(&json!(2)));
    assert!(!config.is_overridden(&key("transfer.maxConcurrent")));
    assert!(config.is_default());
}

#[test]
fn setting_a_value_to_its_default_still_counts_as_overridden() {
    // ★ The distinction the whole module is for. A setting the user has never touched is not the same as one they
    // set to the default value: the first is unmarked in a settings screen and restored by nothing, the second is
    // marked as changed and restored by a reset.
    let mut config = Config::new(catalog());
    config
        .apply(&[(key("transfer.maxConcurrent"), json!(2))], &[])
        .expect("apply");

    assert!(config.is_overridden(&key("transfer.maxConcurrent")));
    assert_eq!(config.get(&key("transfer.maxConcurrent")), Some(&json!(2)));
    assert!(!config.is_default());
}

#[test]
fn unsetting_removes_the_override_rather_than_writing_the_default() {
    // Writing the default would leave the key overridden, so a reset would not reset it and the screen would keep
    // showing it as changed.
    let mut config = Config::new(catalog());
    config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("set");
    let changed = config.apply(&[], &[key("ui.locale")]).expect("unset");

    assert_eq!(changed, 1);
    assert!(!config.is_overridden(&key("ui.locale")));
    assert_eq!(config.get(&key("ui.locale")), Some(&json!("en")));
}

#[test]
fn a_key_the_catalogue_does_not_know_lives_as_an_override() {
    // ★ The reason the boundary is a bag: an interface adds a setting without a kernel release. A catalogue that
    // whitelisted would refuse this, and every new setting would need a kernel version.
    let mut config = Config::new(catalog());
    config
        .apply(&[(key("companion.showAvatar"), json!(false))], &[])
        .expect("apply");

    assert_eq!(config.get(&key("companion.showAvatar")), Some(&json!(false)));
    assert!(config.is_overridden(&key("companion.showAvatar")));
    // And it survives into the bag, which is what the interface reads.
    let values = config.values();
    assert_eq!(values["companion.showAvatar"], json!(false));
}

#[test]
fn the_bag_carries_the_defaults_as_well_as_the_overrides() {
    // A screen that had to know each default would be a second copy of the catalogue, and the two would disagree at
    // the first change.
    let mut config = Config::new(catalog());
    config.apply(&[(key("ui.locale"), json!("zh"))], &[]).expect("apply");

    let values = config.values();
    assert_eq!(values["ui.locale"], json!("zh"));
    assert_eq!(values["transfer.maxConcurrent"], json!(2));
    assert_eq!(values["transfer.resume"], json!(true));
}

#[test]
fn the_snapshot_says_which_keys_the_user_chose() {
    let mut config = Config::new(catalog());
    config
        .apply(&[(key("ui.locale"), json!("zh")), (key("transfer.resume"), json!(false))], &[])
        .expect("apply");

    let snapshot = config.snapshot();
    assert_eq!(snapshot.overridden, vec!["transfer.resume", "ui.locale"]);
    assert_eq!(snapshot.values["transfer.resume"], json!(false));
}

#[test]
fn an_unknown_key_is_not_overridden() {
    // Answering `true` for a key nothing has written would make a settings screen mark a row the user has never
    // seen.
    let config = Config::new(catalog());
    assert!(!config.is_overridden(&key("nobody.setThis")));
    assert_eq!(config.get(&key("nobody.setThis")), None);
}

#[test]
fn a_reset_forgets_everything_and_says_how_much() {
    let mut config = Config::new(catalog());
    config
        .apply(&[(key("ui.locale"), json!("zh")), (key("a.b"), json!(1))], &[])
        .expect("apply");
    assert_eq!(config.reset(), 2);
    assert!(config.is_default());
    assert_eq!(config.get(&key("ui.locale")), Some(&json!("en")));
    // And a second reset reports nothing, because there was nothing to forget.
    assert_eq!(config.reset(), 0);
}
