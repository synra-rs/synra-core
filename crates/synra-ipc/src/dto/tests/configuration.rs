use super::super::{ConfigPatch, ConfigSnapshot};

#[test]
fn a_patch_sets_and_unsets_keys() {
    let mut patch = ConfigPatch::default();
    patch.set.insert("ui.theme".to_owned(), serde_json::json!("dark"));
    patch.unset.push("ui.locale".to_owned());

    assert!(!patch.is_empty());
    assert_eq!(patch.len(), 2);
    assert_eq!(patch.has_conflict(), None);
}

#[test]
fn an_empty_patch_says_so() {
    // So the shell can refuse a no-op call rather than waking the kernel for it.
    assert!(ConfigPatch::default().is_empty());
    assert_eq!(ConfigPatch::default().len(), 0);
}

#[test]
fn a_key_that_is_both_set_and_unset_is_reported() {
    // Refused rather than resolved by precedence: the caller meant one of the two, and picking for them
    // produces a setting that is the opposite of what they asked for half the time.
    let mut patch = ConfigPatch::default();
    patch.set.insert("ui.theme".to_owned(), serde_json::json!("dark"));
    patch.unset.push("ui.theme".to_owned());
    assert_eq!(patch.has_conflict(), Some("ui.theme"));
}

#[test]
fn a_config_patch_round_trips() {
    let mut patch = ConfigPatch::default();
    patch.set.insert("a".to_owned(), serde_json::json!(1));
    patch.unset.push("b".to_owned());
    let json = serde_json::to_string(&patch).expect("serialises");
    let back: ConfigPatch = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, patch);
}

#[test]
fn an_empty_config_snapshot_keeps_the_required_override_list() {
    let snapshot = ConfigSnapshot {
        values: serde_json::json!({}),
        overridden: Vec::new(),
    };
    let json = serde_json::to_value(&snapshot).expect("serialises");
    assert_eq!(json, serde_json::json!({ "values": {}, "overridden": [] }));
    let back: ConfigSnapshot = serde_json::from_value(json).expect("deserialises");
    assert_eq!(back, snapshot);
}

#[test]
fn a_config_snapshot_carries_which_keys_were_overridden() {
    // So the settings screen can mark a value the user changed from the default.
    let snapshot = ConfigSnapshot {
        values: serde_json::json!({ "ui.theme": "dark" }),
        overridden: vec!["ui.theme".to_owned()],
    };
    let json = serde_json::to_string(&snapshot).expect("serialises");
    assert!(json.contains("overridden"), "{json}");
    let back: ConfigSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, snapshot);
}
