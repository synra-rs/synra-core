use super::*;

// ── Consent ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn consent_records_one_decision_per_capability_and_unlocks_the_plugin() {
    // ★ The writer that only tests had. `load_one` refuses a plugin with no decisions on record, so before this command a
    // plugin was installable, visible and enable-able and permanently unloadable: everything the user could see said it
    // was installed, and the one thing that decides whether it runs said nobody had ever approved it.
    let dir = TempDir::new("consent-records");
    let runtime = runtime(dir.path());
    let plugin = "@acme/two-caps";
    write_plugin(
        &runtime.plugins_dir,
        plugin,
        r#"{"cap": "log:info"}, {"cap": "device:list"}"#,
    );
    install(&runtime, plugin, 1, 0);

    runtime
        .plugin_consent(plugin, &["log:info".to_owned()])
        .expect("the decision is recorded");

    let grants = runtime.db().plugin_grants(plugin).expect("the decisions");
    let decisions: std::collections::BTreeMap<String, bool> = grants
        .into_iter()
        .map(|row| (row.capability, row.granted))
        .collect();
    assert_eq!(decisions.get("log:info"), Some(&true));
    // ★ A capability the user did not name is **denied**, not left absent. An absent row means "no decision", and the
    // loader would then find no digest to compare against — a plugin that cannot be loaded for a reason nobody can see.
    assert_eq!(decisions.get("device:list"), Some(&false));

    let row = runtime
        .db()
        .plugins()
        .expect("the rows")
        .into_iter()
        .find(|row| row.plugin_id == plugin)
        .expect("the row");
    assert!(row.trusted, "a recorded decision is what trust means here");

    // And the loader accepts it now, which is the point: the grants come from the decision rather than from the
    // manifest's own declaration.
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert!(
        summary
            .loaded
            .iter()
            .any(|loaded| loaded.to_string() == plugin),
        "{summary:?}"
    );
}

#[test]
fn partial_consent_loads_the_plugin_with_only_what_was_allowed() {
    // ★ The behaviour the two hosts disagreed about, asserted where it is visible: the loader is given the **granted
    // subset**, not the manifest's declarations. `log:*` is in the set and `device:list` is not — so the plugin runs and
    // is refused at the gate for the capability the user declined, which is what a capability gate is for.
    let dir = TempDir::new("consent-partial");
    let runtime = runtime(dir.path());
    let plugin = "@acme/partial";
    write_plugin(
        &runtime.plugins_dir,
        plugin,
        r#"{"cap": "log:*"}, {"cap": "device:list"}"#,
    );
    install(&runtime, plugin, 1, 0);

    runtime
        .plugin_consent(plugin, &["log:*".to_owned()])
        .expect("the decision is recorded");

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert!(
        summary
            .loaded
            .iter()
            .any(|loaded| loaded.to_string() == plugin),
        "{summary:?}"
    );

    let id = synra_protocol::PluginId::try_from(plugin.to_owned()).expect("a plugin id");
    let grants = set.grants(&id).expect("the grants the loader built");
    assert!(grants.contains(&synra_capability::Capability::parse("log:*").expect("a capability")));
    assert!(
        !grants
            .contains(&synra_capability::Capability::parse("device:list").expect("a capability")),
        "the declined capability must not be in the grant set"
    );
}

#[test]
fn consent_for_a_capability_the_plugin_did_not_ask_for_is_refused() {
    // A typo is the common case and an attempt to widen the decision is the other one; neither should become a row.
    let dir = TempDir::new("consent-unknown");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/quiet",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/quiet", 0, 0);

    let refused = runtime
        .plugin_consent("@acme/quiet", &["device:list".to_owned()])
        .expect_err("the plugin never asked for it");

    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(refused.message.contains("device:list"), "{refused:?}");
    // ★ Nothing is written: a partial record would leave decisions about a document the user never decided.
    assert!(
        runtime
            .db()
            .plugin_grants("@acme/quiet")
            .expect("the decisions")
            .is_empty()
    );
}

#[test]
fn consent_for_a_plugin_that_is_not_installed_is_refused() {
    let dir = TempDir::new("consent-missing");
    let runtime = runtime(dir.path());

    let refused = runtime
        .plugin_consent("@acme/ghost", &["log:info".to_owned()])
        .expect_err("nothing is there");

    assert_eq!(refused.code, ErrorCode::PluginNotInstalled);
    assert!(refused.message.contains("@acme/ghost"), "{refused:?}");
}

#[test]
fn denying_every_capability_records_the_refusal_and_withdraws_trust() {
    let dir = TempDir::new("consent-deny-all");
    let runtime = runtime(dir.path());
    let plugin = "@acme/denied";
    write_plugin(&runtime.plugins_dir, plugin, r#"{"cap": "log:info"}"#);
    install(&runtime, plugin, 1, 1);

    runtime
        .plugin_consent(plugin, &[])
        .expect("the refusal is recorded");

    let grants = runtime.db().plugin_grants(plugin).expect("the decisions");
    assert_eq!(grants.len(), 1);
    assert!(!grants[0].granted, "not naming a capability denies it");
    let row = runtime
        .db()
        .plugins()
        .expect("the rows")
        .into_iter()
        .find(|row| row.plugin_id == plugin)
        .expect("the row");
    // ★ And it loses the trust an earlier build may have set: a decision to deny everything is not approval, and leaving
    // `trusted` set would leave the plugin one `enable` away from running with nothing granted.
    assert!(!row.trusted);
}
