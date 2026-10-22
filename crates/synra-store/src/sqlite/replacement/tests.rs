use super::*;

fn database() -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("database");
    db.migrate().expect("schema");
    db.insert_plugin("@acme/hello", true, true, "good", 1, 1)
        .expect("plugin");
    db.record_plugin_version("@acme/hello", "1.0.0", "plugin.wasm", "old", "{}", 1)
        .expect("version");
    db.record_grants(
        "@acme/hello",
        &[
            ("log:*".to_owned(), true),
            ("device:list".to_owned(), false),
            ("device:send:*".to_owned(), true),
        ],
        1,
        "old-manifest",
    )
    .expect("decisions");
    db
}

fn replacement<'a>(capabilities: &'a [String]) -> PluginReplacement<'a> {
    PluginReplacement {
        plugin_id: "@acme/hello",
        version: "1.1.0",
        artifact: "plugin.wasm",
        digest: "new",
        manifest: "{}",
        manifest_digest: "new-manifest",
        previous_manifest_digest: Some("old-manifest"),
        capabilities,
        now_ms: 2,
    }
}

#[test]
fn a_replacement_rebinds_existing_choices_and_removes_obsolete_grants() {
    let db = database();
    db.replace_plugin_version(&replacement(&[
        "log:*".to_owned(),
        "device:list".to_owned(),
    ]))
    .expect("commit");
    assert_eq!(
        db.active_plugin("@acme/hello")
            .expect("version")
            .expect("installed")
            .version,
        "1.1.0"
    );
    let grants = db.plugin_grants("@acme/hello").expect("decisions");
    assert_eq!(grants.len(), 2);
    assert!(
        grants
            .iter()
            .all(|grant| grant.manifest_digest == "new-manifest" && grant.decided_ms == 1)
    );
    assert!(
        grants
            .iter()
            .any(|grant| grant.capability == "device:list" && !grant.granted)
    );
    assert!(db.plugins().expect("row")[0].should_run());
}

#[test]
fn consecutive_permissionless_updates_keep_the_existing_trust() {
    let db = database();
    db.replace_plugin_version(&replacement(&[]))
        .expect("remove permissions");
    assert!(
        db.plugin_grants("@acme/hello")
            .expect("decisions")
            .is_empty()
    );
    let mut next = replacement(&[]);
    next.version = "1.2.0";
    next.previous_manifest_digest = Some("new-manifest");
    db.replace_plugin_version(&next)
        .expect("permissionless update");
    assert!(db.plugins().expect("row")[0].should_run());
    assert!(
        db.plugin_grants("@acme/hello")
            .expect("decisions")
            .is_empty()
    );
}

#[test]
fn a_failed_version_write_restores_the_version_flags_and_grants_together() {
    let db = database();
    db.connection.execute_batch("CREATE TRIGGER refuse_new_version BEFORE INSERT ON plugin_versions WHEN NEW.version = '1.1.0' BEGIN SELECT RAISE(ABORT, 'disk refuses version'); END").expect("failure injection");
    let before = db.plugin_grants("@acme/hello").expect("decisions");
    assert!(
        db.replace_plugin_version(&replacement(&["log:*".to_owned()]))
            .is_err()
    );
    assert_eq!(
        db.active_plugin("@acme/hello")
            .expect("version")
            .expect("installed")
            .version,
        "1.0.0"
    );
    assert_eq!(db.plugin_grants("@acme/hello").expect("decisions"), before);
    assert!(db.plugins().expect("row")[0].should_run());
}

#[test]
fn consent_for_a_different_manifest_is_never_carried_forward() {
    let db = database();
    db.record_grants(
        "@acme/hello",
        &[("log:*".to_owned(), true)],
        2,
        "other-manifest",
    )
    .expect("stale choice");
    db.replace_plugin_version(&replacement(&["log:*".to_owned()]))
        .expect("commit");
    let rows = db.plugins().expect("rows");
    assert!(rows[0].enabled, "the switch is still the user's preference");
    assert!(!rows[0].trusted, "a stale decision is not authorization");
    assert!(
        db.plugin_grants("@acme/hello")
            .expect("decisions")
            .is_empty()
    );
}

#[test]
fn a_changed_publisher_or_permission_list_clears_approval() {
    let db = database();
    let capabilities = ["log:*".to_owned(), "device:list".to_owned()];
    let mut next = replacement(&capabilities);
    next.previous_manifest_digest = None;
    db.replace_plugin_version(&next).expect("commit");
    let rows = db.plugins().expect("rows");
    assert!(!rows[0].enabled && !rows[0].trusted);
    assert!(
        db.plugin_grants("@acme/hello")
            .expect("decisions")
            .is_empty()
    );
}
