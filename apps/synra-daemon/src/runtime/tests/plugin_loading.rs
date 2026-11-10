use super::*;

#[test]
fn an_enabled_and_trusted_plugin_is_actually_loaded() {
    // ★ This is the test the hardcoded `"loaded": false` made impossible to write. Before the load pass existed there
    // was no code path from a database row to a compiled component, so there was nothing here to assert.
    let dir = TempDir::new("load-one");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);

    consent(&runtime, "@acme/hello", &["log:info"]);
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert_eq!(
        summary.len(),
        1,
        "the one plugin that should run did; refused: {:?}",
        summary.refused
    );
    assert!(summary.contains(
        &synra_protocol::ids::PluginId::try_from("@acme/hello".to_owned()).expect("an id")
    ));
    assert!(
        summary.refused.is_empty(),
        "nothing was refused: {:?}",
        summary.refused
    );
}

#[test]
fn a_plugin_the_user_never_answered_about_is_not_loaded_even_when_it_is_trusted() {
    // ★ The consistency check, and the reason `trusted = 1` stopped being an authorisation.
    //
    // The grants used to come from the manifest's own declaration, so a row saying "the user trusts this" was enough and
    // a plugin received exactly what it asked for. A row in that state — trusted, with nothing recorded — is what a
    // pre-consent build left behind, and it must not load: there is no decision behind the flag.
    let dir = TempDir::new("no-consent");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);
    // Deliberately no `consent`.

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "nothing may be loaded: {summary:?}");
    let refused = summary.refused.first().expect("a refusal, not silence");
    assert_eq!(refused.plugin_id, "@acme/hello");
    assert!(
        refused.reason.contains("confirmed by the user"),
        "the reason has to be one a user can act on: {}",
        refused.reason
    );
}

#[test]
fn a_plugin_whose_manifest_changed_after_consent_needs_confirming_again() {
    // ★ Why the decision is recorded against a digest rather than against the plugin.
    //
    // A user approves a plugin that asks for `log:*`, and then the package is replaced by one that also asks for
    // `device:list`. The decisions on record are about a **different document**, so the honest answer is "confirm this
    // again" — not "run it with less than it says it needs", which produces a plugin that appears to work and fails at
    // one thing.
    let dir = TempDir::new("stale-consent");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);
    consent(&runtime, "@acme/hello", &["log:info"]);

    // The package is replaced. Same id, same version, one more capability — a change an author can make without bumping
    // anything, which is exactly why the bytes are what is hashed.
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}, {"cap": "device:list"}"#,
    );

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "nothing may be loaded: {summary:?}");
    let refused = summary.refused.first().expect("a refusal, not silence");
    assert!(
        refused
            .reason
            .contains("changed since the user confirmed it"),
        "the reason has to say what happened: {}",
        refused.reason
    );
}

#[test]
fn the_grants_a_plugin_runs_with_are_the_ones_the_user_gave_it() {
    // ★ The difference the whole change exists for, asserted at the only place it is observable from outside.
    //
    // The manifest declares two capabilities; the user granted one. The plugin must load with **one**, because the set
    // it runs with is the user's decision rather than the author's request. Before this, the two were the same thing by
    // construction and no test could tell them apart.
    let dir = TempDir::new("granted-narrow");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "log:info"}, {"cap": "device:list"}"#,
    );
    install(&runtime, "@acme/hello", 1, 1);
    consent(&runtime, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert_eq!(
        summary.len(),
        1,
        "the plugin still runs: {:?}",
        summary.refused
    );

    // Read back through the set rather than the database, so this asserts what the *plugin* was given.
    let held = set
        .grants(&synra_protocol::ids::PluginId::try_from("@acme/hello".to_owned()).expect("an id"))
        .expect("the plugin is loaded");
    let held: Vec<String> = held.iter().map(ToString::to_string).collect();
    assert_eq!(
        held,
        vec!["log:info".to_owned()],
        "the granted set, not the requested one: {held:?}"
    );
}

#[test]
fn a_plugin_the_user_never_trusted_is_not_loaded_and_not_refused() {
    // `should_run` is `enabled && trusted`, so an untrusted plugin is a decision the user has not made yet. Reporting
    // it as a refusal would put a plugin author on a bug report for a plugin that has not been approved for anything.
    let dir = TempDir::new("load-untrusted");
    let runtime = runtime(dir.path());
    write_plugin(
        &runtime.plugins_dir,
        "@acme/hello",
        r#"{"cap": "net:fetch:*"}"#,
    );
    install(&runtime, "@acme/hello", 1, 0);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "an untrusted plugin is not loadable");
    assert!(
        summary.refused.is_empty(),
        "and untrusted is not a failure: {:?}",
        summary.refused
    );
}

#[test]
fn a_ui_only_plugin_is_refused_rather_than_loaded_because_it_has_no_headless_half() {
    // A UI plugin is a working plugin that does not run here — its interface is served by the shell. Calling that a
    // failure would be wrong, and calling it loaded would be a lie, so it is named as what it is.
    let dir = TempDir::new("load-ui-only");
    let runtime = runtime(dir.path());
    let directory = plugin_dir(&runtime.plugins_dir, "@acme/ui-only");
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    std::fs::write(
        directory.join("manifest.json"),
        manifest_json(
            "@acme/ui-only",
            "",
            r#"{"ui": {"artifact": "dist", "entry": "index.html"}}"#,
        ),
    )
    .expect("a manifest");
    install(&runtime, "@acme/ui-only", 1, 1);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db,
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty());
    assert_eq!(summary.refused.len(), 1);
    assert!(
        summary.refused[0].reason.contains("headless"),
        "{}",
        summary.refused[0].reason
    );
}
