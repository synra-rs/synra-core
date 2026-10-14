//! The configuration's own tests, moved out of the flat file unchanged.

use super::*;
use serde_json::json;

fn key(text: &str) -> SettingKey {
    SettingKey::parse(text).expect("a valid key")
}

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog
        .register(
            Setting::new("transfer.maxConcurrent", SettingKind::Integer, json!(2), "how many at once")
                .expect("a valid setting"),
        )
        .register(
            Setting::new("transfer.resume", SettingKind::Bool, json!(true), "continue a broken transfer")
                .expect("a valid setting"),
        )
        .register(
            Setting::new("ui.locale", SettingKind::Text, json!("en"), "the language")
                .expect("a valid setting"),
        )
        .register(
            Setting::new("internal.schemaVersion", SettingKind::Integer, json!(1), "written by the kernel")
                .expect("a valid setting")
                .reserved(),
        );
    catalog
}

// ── Keys ──────────────────────────────────────────────────────────────────────────────────────

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

// ── Kinds ─────────────────────────────────────────────────────────────────────────────────────

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

// ── Defaults and overrides ────────────────────────────────────────────────────────────────────

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

// ── Patches ───────────────────────────────────────────────────────────────────────────────────

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

// ── Files ─────────────────────────────────────────────────────────────────────────────────────

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

// ── The catalogue ─────────────────────────────────────────────────────────────────────────────

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
