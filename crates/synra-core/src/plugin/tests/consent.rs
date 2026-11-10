use super::*;

#[test]
fn a_plugin_without_a_recorded_decision_is_refused_rather_than_run_with_its_request() {
    let root = scratch("no-consent");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal, not silence");
    assert!(reason.contains("confirmed by the user"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_manifest_that_changed_since_consent_needs_confirming_again() {
    let root = scratch("stale-consent");
    let plugins = root.join("plugins");
    let text = write_plugin(&plugins, "@acme/hello", &["log:info"]);
    let db = database();
    install(&db, "@acme/hello", true, true);
    // A decision about a different document: the digest is the contract's own hex digest, not an arbitrary string.
    db.record_grants("@acme/hello", &[("log:info".to_owned(), true)], 200, "a different document")
        .expect("the stale decision");
    let _ = text;

    let (mut set, _backend) = set();
    let summary = load_installed(
        &mut set,
        &parking_lot::Mutex::new(db),
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let reason = summary.refusal_for("@acme/hello").expect("a refusal, not silence");
    assert!(reason.contains("changed since the user confirmed it"), "{reason}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_revoked_version_is_disabled_in_the_store_and_refused() {
    let root = scratch("revoked");
    let plugins = root.join("plugins");
    write_plugin(&plugins, "@bad/plugin", &["log:info"]);
    let db = database();
    install(&db, "@bad/plugin", true, true);
    consent(&db, &plugins, "@bad/plugin", &["log:info"]);
    let revoked = synra_plugin_api::revocation::RevocationList::parse(
        r#"{"revoked": [{"plugin": "@bad/plugin", "versions": ["1.0.0"], "reason": "malicious code"}]}"#,
    )
    .expect("a revocation list");

    let (mut set, _backend) = set();
    let db = parking_lot::Mutex::new(db);
    let summary = load_installed(
        &mut set,
        &db,
        &plugins,
        &synra_observe::crash::StartupVerdict::Clean,
        &revoked,
    );

    let reason = summary.refusal_for("@bad/plugin").expect("a refusal");
    assert!(reason.contains("malicious code"), "{reason}");
    assert!(reason.contains("disabled"), "{reason}");
    let row = db
        .lock()
        .plugins()
        .expect("the table")
        .into_iter()
        .find(|row| row.plugin_id == "@bad/plugin");
    assert!(
        !row.expect("the row").enabled,
        "a revoked plugin stays enabled and is tried again next start"
    );
    let _ = std::fs::remove_dir_all(&root);
}
