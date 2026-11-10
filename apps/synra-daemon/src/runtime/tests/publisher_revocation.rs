use super::*;

#[test]
fn revoking_one_plugin_leaves_the_others_alone() {
    // """ + S + """ The same class of guard as the sweep's, for the kernel's other destructive action.
    //
    // Revoking a plugin **disables a row**, and a revocation that matched too widely — a comparison on the wrong field, a
    // query missing its identifier — would disable plugins the list never named. The user sees a plugin they installed and
    // approved stop working, with a reason about a version that is not theirs, and no way to tell what happened.
    //
    // So the assertion is not "the revoked one was disabled". It is that **the other one was not**, which is the claim a
    // too-wide match breaks and the claim nothing was checking.
    let dir = TempDir::new("load-revoked-others");
    let runtime = runtime(dir.path());
    for id in ["@bad/plugin", "@good/plugin"] {
        write_plugin(&runtime.plugins_dir, id, r#"{"cap": "log:info"}"#);
        install(&runtime, id, 1, 1);
        consent(&runtime, id, &["log:info"]);
    }

    // A list that names one plugin at the version both of them have, so a match on the version alone would catch both and a
    // match on the name alone would catch only the intended one. Both facts matter, which is why the list is written this
    // way rather than with a version only one plugin has.
    let list = synra_plugin_api::revocation::RevocationList::parse(
        r#"{"revoked":[{"plugin":"@bad/plugin","versions":["1.2.3"],"reason":"malicious code"}]}"#,
    )
    .expect("a list");
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &list,
    );

    let rows: std::collections::BTreeMap<String, bool> = runtime
        .db()
        .plugins()
        .expect("the rows")
        .into_iter()
        .map(|row| (row.plugin_id, row.enabled))
        .collect();

    assert_eq!(
        rows.get("@bad/plugin"),
        Some(&false),
        "the revoked one is disabled"
    );
    assert_eq!(
        rows.get("@good/plugin"),
        Some(&true),
        "a plugin the list does not name was disabled too: {rows:?}"
    );
    // And it still loaded, which is the consequence a user would notice.
    assert_eq!(summary.len(), 1, "refused: {:?}", summary.refused);
    assert!(summary.contains(
        &synra_protocol::ids::PluginId::try_from("@good/plugin".to_owned()).expect("an id")
    ));
}

#[test]
fn a_revoked_installed_version_is_refused_and_disabled() {
    // ★ The design's behaviour for an installed revoked version: *"disable immediately, and tell the user"*. Both halves are
    // asserted, because either alone is a plugin that comes back:
    //
    // * refusing to **load** it this run is not disabling it — the row stays enabled and the next start tries again;
    // * disabling the **row** without saying why leaves a user with a plugin that switched itself off.
    let dir = TempDir::new("load-revoked");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@bad/plugin",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@bad/plugin", 1, 1);
    consent(&runtime, "@bad/plugin", &["log:info"]);

    // And without the list it loads, so the test is about the list rather than about the plugin.
    let (mut set, _backend) = loader();
    let without = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert_eq!(without.len(), 1, "refused: {:?}", without.refused);

    let list = synra_plugin_api::revocation::RevocationList::parse(
        r#"{"revoked":[{"plugin":"@bad/plugin","versions":["1.2.3"],"reason":"malicious code"}]}"#,
    )
    .expect("a list");
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &list,
    );

    assert!(
        summary.is_empty(),
        "a revoked plugin was loaded: {:?}",
        summary.loaded
    );
    let refused = summary.refused.first().expect("a refusal");
    assert_eq!(refused.plugin_id, "@bad/plugin");
    // The reason reaches the user, and it says the disable happened rather than only that loading was skipped.
    assert!(
        refused.reason.contains("malicious code"),
        "{}",
        refused.reason
    );
    assert!(refused.reason.contains("disabled"), "{}", refused.reason);

    // ★ And the row is off, which is the half that survives a restart.
    let row = runtime
        .db()
        .plugins()
        .expect("the rows")
        .into_iter()
        .find(|row| row.plugin_id == "@bad/plugin")
        .expect("the row");
    assert!(
        !row.enabled,
        "a revoked plugin is still enabled in the store"
    );
}
