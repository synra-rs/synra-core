use super::*;

#[test]
fn activation_carries_the_hosts_locale_and_theme() {
    // ★ `activate` receives a JSON object, and the SDK's own example reads `config.locale`. An empty object withheld a
    // fact the host already knows; this asserts the two fields are the host's own answers rather than constants.
    let config: serde_json::Value =
        serde_json::from_str(&activation_config(&RefusingHost)).expect("the config is JSON");
    assert_eq!(config["locale"], "en-GB");
    assert_eq!(config["darkMode"], false);
}

#[test]
fn a_plugin_that_refuses_to_activate_is_not_left_loaded() {
    // ★ Loading is not activation. A plugin that compiles but refuses `activate` is not fit to answer, and leaving it in
    // the set would let it match a share it cannot execute. The refusal is the plugin's own sentence, not a code.
    let root = scratch("activate-refused");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, backend) = set();
    backend.script_for(
        "@acme/hello",
        &Work::Activate { config_json: activation_config(&RefusingHost) },
        Scripted::Failed {
            code: "invalidArgument".to_owned(),
            message: "the settings are nonsense".to_owned(),
            details: None,
        },
    );

    let summary = load_installed_with_config(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
        &activation_config(&RefusingHost),
    );

    assert!(summary.is_empty(), "a plugin that refused to start was left loaded: {:?}", summary.loaded);
    let reason = summary.refusal_for("@acme/hello").expect("a refusal, not silence");
    assert!(reason.contains("activate"), "{reason}");
    assert!(reason.contains("the settings are nonsense"), "the plugin's own sentence is carried: {reason}");
    assert!(!set.contains(&PluginId::try_from("@acme/hello".to_owned()).expect("an id")));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plugin_the_user_enabled_and_confirmed_loads_with_the_granted_capabilities() {
    // ★ The difference the whole loader exists for, asserted at the place it is observable: the manifest declares two
    // capabilities and the user granted one, so the plugin must run with one. Before consent was consulted, the two
    // were the same thing by construction and no test could tell them apart.
    let root = scratch("granted-narrow");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info", "device:list"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert_eq!(summary.len(), 1, "refused: {:?}", summary.refused);
    let id = PluginId::try_from("@acme/hello".to_owned()).expect("an id");
    let held: Vec<String> = set.grants(&id).expect("the plugin is loaded").iter().map(ToString::to_string).collect();
    assert_eq!(held, vec!["log:info".to_owned()], "the granted set, not the requested one: {held:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn safe_mode_loads_nothing_and_says_why() {
    // ★ Safe mode has to stop a *good* plugin, because the host cannot know which one is crashing until it starts them.
    // The verdict is reached the way a host reaches it — three reports, then the store's decision — rather than by
    // hand-building the enum, which would only prove that a made-up value returns false.
    let root = scratch("safe-mode");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    consent(&db, &plugins, "@acme/hello", &["log:info"]);

    let crashes = synra_observe::crash::CrashStore::new(&root);
    for offset in 0..synra_observe::crash::SAFE_MODE_THRESHOLD {
        crashes
            .write(&synra_observe::crash::CrashReport::new(
                1_000 + i64::try_from(offset).expect("a small offset"),
                "1.0.0",
                Some("src/plugin.rs:42".to_owned()),
                Some("the plugin panicked".to_owned()),
                None,
                None,
                None,
            ))
            .expect("the report is written");
    }
    let safe = crashes.verdict(1_000);
    assert!(!safe.allows_plugins(), "three crashes in one location did not reach safe mode: {safe:?}");

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &safe,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "safe mode loaded something: {:?}", summary.loaded);
    // ★ Not in `refused`: this plugin did not fail, it was never examined. Reporting it as a refusal would put a plugin
    // author on a bug report for the host's own decision.
    assert!(summary.refused.is_empty(), "a plugin was blamed for the host's decision: {:?}", summary.refused);
    let why = summary.safe_mode.as_deref().expect("safe mode must explain itself");
    assert!(why.contains("crashed 3 times"), "{why}");
    let _ = std::fs::remove_dir_all(&root);
}
