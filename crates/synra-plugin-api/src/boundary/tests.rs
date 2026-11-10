use super::*;

// ── Outcome ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_success_and_a_completion_are_different_answers() {
    // ★ "The call succeeded and produced nothing" and "the call succeeded and produced an empty string" are
    // different, and a caller that had to tell them apart from the payload's emptiness would get it wrong for the
    // one function that legitimately returns `""`.
    assert_ne!(Outcome::done(), Outcome::ok(""));
    assert!(Outcome::done().is_ok());
    assert_eq!(Outcome::done().payload(), None);
    assert_eq!(Outcome::ok("").payload(), Some(""));
}

#[test]
fn a_refusal_carries_a_code_and_a_key() {
    let refused = Outcome::refused("device_offline", "error.deviceOffline");
    assert!(!refused.is_ok());
    assert_eq!(refused.error_code(), Some("device_offline"));
    // A key rather than a sentence: a sentence composed here would be composed once, in whatever language the
    // kernel was built for.
    assert!(refused.message.as_deref().is_some_and(|key| key.starts_with("error.")));
}

#[test]
fn an_outcome_narrows_on_the_flag_rather_than_on_a_payload() {
    // The field a caller branches on is `ok`, and the accessors are what make a wrong read obvious: reading the
    // payload of a refusal gives `None` rather than the empty string a caller might mistake for a result.
    assert_eq!(Outcome::refused("timeout", "error.timeout").payload(), None);
    assert_eq!(Outcome::done().error_code(), None);
}

#[test]
fn the_wire_shape_omits_what_is_absent() {
    // A `null` where the contract says "omitted" is a difference the component model does not accept, so the
    // `skip_serializing_if` on each optional field is what makes the Rust type and the WIT record agree.
    let json = serde_json::to_string(&Outcome::done()).expect("serialises");
    assert_eq!(json, r#"{"ok":true}"#);
    // camelCase, because the contract's field names are, and a `snake_case` key would be a field the other side
    // does not have.
    let json = serde_json::to_string(&Outcome::refused("a_b", "error.aB")).expect("serialises");
    assert!(json.contains("\"code\":\"a_b\""), "{json}");
}

#[test]
fn an_outcome_round_trips() {
    for outcome in [Outcome::done(), Outcome::ok("payload"), Outcome::refused("code", "error.key")] {
        let json = serde_json::to_string(&outcome).expect("serialises");
        let back: Outcome = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, outcome);
    }
}

// ── LogLevel ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_level_is_listed_and_counted() {
    // A level added to the variants and not to `all` would be one nothing emits, and the compiler cannot see it
    // because `all` is a slice.
    assert_eq!(LogLevel::all().len(), 5);
    for level in LogLevel::all() {
        // And each level's spelling is its own: two levels sharing a spelling would be one level with two names.
        assert!(!level.as_str().is_empty());
    }
    let mut spellings: Vec<&str> = LogLevel::all().iter().map(|level| level.as_str()).collect();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(spellings.len(), LogLevel::all().len(), "a spelling repeats");
}

#[test]
fn the_levels_order_by_severity() {
    // A caller filtering at `warn` compares, so the ordering is part of the contract rather than an accident of the
    // declaration order.
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Error);
}

#[test]
fn a_level_spells_itself_lower_case_on_the_wire() {
    assert_eq!(LogLevel::Trace.as_str(), "trace");
    assert_eq!(LogLevel::Error.as_str(), "error");
    assert_eq!(LogLevel::Warn.to_string(), "warn");
    assert_eq!(
        serde_json::to_string(&LogLevel::Info).expect("serialises"),
        "\"info\""
    );
}

// ── DeviceTarget ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_device_target_carries_identifiers_and_not_addresses() {
    // ★ The rule this type exists for. An address is a capability the plugin was not granted: `device:send:*` says
    // it may send to a device, not that it may learn the shape of the user's network. A device list carrying
    // addresses would leak that to every plugin holding `device:list`.
    let target = DeviceTarget::new("dev_a");
    let json = serde_json::to_string(&target).expect("serialises");
    for forbidden in ["address", "addr", "ip", "port", "host", "socket"] {
        assert!(!json.contains(forbidden), "a device target carries {forbidden}: {json}");
    }
    // What it does carry, which is what a plugin needs to address a call and to show a row.
    assert_eq!(target.device_id, "dev_a");
    assert!(target.online);
    assert!(target.paired);
}

#[test]
fn a_device_target_omits_a_name_it_does_not_have() {
    // The kernel has a name for a paired device and often not for one it has merely seen. A `null` where the
    // contract says "omitted" is a difference the component model does not accept.
    let json = serde_json::to_string(&DeviceTarget::new("dev_a")).expect("serialises");
    assert!(!json.contains("displayName"), "{json}");

    let named = DeviceTarget {
        display_name: Some("Laptop".to_owned()),
        ..DeviceTarget::new("dev_a")
    };
    let json = serde_json::to_string(&named).expect("serialises");
    assert!(json.contains("\"displayName\":\"Laptop\""), "{json}");
}

#[test]
fn a_device_target_round_trips() {
    let target = DeviceTarget {
        display_name: Some("Laptop".to_owned()),
        ..DeviceTarget::new("dev_a")
    };
    let json = serde_json::to_string(&target).expect("serialises");
    let back: DeviceTarget = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, target);
}

#[test]
fn every_type_is_non_exhaustive_for_the_plugin_side() {
    // A plugin that matched a level exhaustively would have its build broken by a level the contract gained, and
    // the arm it added would then hide every future one. A compile-time property asserted here so the file states
    // it rather than relying on a reader to notice the attribute.
    assert!(LogLevel::all().len() >= 5);
    // The types are `#[non_exhaustive]`, which means this crate cannot construct `Outcome` exhaustively either —
    // and the constructors are how it does.
    let _ = Outcome::done();
    let _ = Outcome::ok("x");
    let _ = Outcome::refused("c", "k");
    let _ = DeviceTarget::new("d");
}
