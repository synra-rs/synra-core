use super::super::SynraDb;
use super::migrated;

/// A database with one plugin in it, untrusted and off.
///
/// A helper because four of the tests below are about the *second* write, and a test whose setup is three lines of SQL
/// spends more of itself on setup than on what it is checking.
fn with_plugin() -> SynraDb {
    let db = migrated();
    db.insert_plugin("@acme/hello", false, false, "healthy", 10, 20).expect("a plugin");
    db
}

#[test]
fn a_plugin_can_be_switched_off_and_on_again() {
    let db = with_plugin();

    assert!(db.set_plugin_enabled("@acme/hello", true, 30).expect("enables"), "the plugin is there");
    let after = db.plugins().expect("reads").remove(0);
    assert!(after.enabled, "the flag reached the row");
    assert_eq!(after.updated_at_ms, 30, "and the time it changed");

    db.set_plugin_enabled("@acme/hello", false, 40).expect("disables");
    assert!(!db.plugins().expect("reads").remove(0).enabled, "and it can be switched back off");
}

#[test]
fn enabling_a_plugin_that_is_not_installed_says_so_rather_than_succeeding() {
    // ★ The fault this catches: `UPDATE` on a missing row changes nothing and reports success, so a caller that
    // believed the `Ok(())` would show the user a plugin that is still off.
    let db = with_plugin();
    assert!(!db.set_plugin_enabled("@acme/nope", true, 30).expect("the write itself is fine"));
    assert_eq!(db.plugins().expect("reads").len(), 1, "and nothing was invented");
}

#[test]
fn trusting_is_not_the_same_act_as_enabling() {
    let db = with_plugin();
    db.set_plugin_enabled("@acme/hello", true, 30).expect("enables");
    let plugin = db.plugins().expect("reads").remove(0);
    assert!(
        !plugin.should_run(),
        "an enabled plugin nobody has trusted must not run — this is what consent is for"
    );

    db.set_plugin_trusted("@acme/hello", true, 31).expect("trusts");
    assert!(
        db.plugins().expect("reads").remove(0).should_run(),
        "and once both are true it runs"
    );
}

#[test]
fn grants_read_back_what_was_written_against_a_manifest() {
    let db = with_plugin();
    // Written through the connection rather than a method, because there is deliberately no writer yet — see the note
    // beside `plugin_grants`. A test that only ever used the reader could not tell the reader from a table that is
    // always empty, so this one writes first and checks the digest survived.
    db.connection
        .execute(
            "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
             VALUES ('@acme/hello', 'net:*.read', 1, 50, 'sha256:abc')",
            [],
        )
        .expect("a grant");
    db.connection
        .execute(
            "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
             VALUES ('@acme/hello', 'store:*.write', 0, 50, 'sha256:abc')",
            [],
        )
        .expect("a refusal");

    let read = db.plugin_grants("@acme/hello").expect("reads");
    assert_eq!(read.len(), 2);
    // Sorted by capability, so the order is the same on every device that read the same decisions.
    assert_eq!(read[0].capability, "net:*.read");
    assert!(read[0].granted);
    assert_eq!(read[0].manifest_digest, "sha256:abc", "the digest survived, which is what an upgrade compares");
    assert!(!read[1].granted, "a refusal is stored as a refusal, not as an absence");
}

#[test]
fn a_plugin_with_no_decisions_has_an_empty_list_rather_than_an_error() {
    let db = with_plugin();
    assert!(db.plugin_grants("@acme/hello").expect("reads").is_empty());
}

#[test]
fn a_plugins_grants_are_not_another_plugins_grants() {
    let db = with_plugin();
    db.insert_plugin("@acme/other", true, true, "healthy", 10, 20).expect("a second plugin");
    db.connection
        .execute(
            "INSERT INTO plugin_grants (plugin_id, capability, granted, decided_ms, manifest_digest) \
             VALUES ('@acme/hello', 'net:*.read', 1, 50, 'sha256:abc')",
            [],
        )
        .expect("a grant");
    assert!(
        db.plugin_grants("@acme/other").expect("reads").is_empty(),
        "the filter is by plugin, not by table"
    );
}

#[test]
fn a_publisher_is_recorded_once_and_a_decision_survives_later_sightings() {
    // ★ "Seen" is not "trusted": an install may record that a key signed a package, and only a user decision may promote
    // it. A second sighting must not reset a decision either — that would make every update forget the answer.
    let db = migrated();
    assert!(db.publishers().expect("reads").is_empty(), "a fresh install has met nobody");

    db.record_publisher("@acme", "AB12 CD34 EF56 7890", "a2V5", 1_000)
        .expect("records");
    let rows = db.publishers().expect("reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].trust, crate::TRUST_SEEN);
    assert_eq!(rows[0].decided_ms, None);

    assert!(!db.set_publisher_trust("@acme", "wrong key", crate::TRUST_TRUSTED, 1_500).expect("stale key"));
    assert!(!db.set_publisher_trust("@acme", "AB12 CD34 EF56 7890", "maybe", 1_500).expect("invalid trust"));
    assert_eq!(db.publishers().expect("rows")[0].decided_ms, None);
    assert!(db.set_publisher_trust("@acme", "AB12 CD34 EF56 7890", crate::TRUST_TRUSTED, 2_000).expect("updates"));
    db.record_publisher("@acme", "AB12 CD34 EF56 7890", "a2V5", 3_000)
        .expect("records again");
    let rows = db.publishers().expect("reads");
    assert_eq!(rows[0].trust, crate::TRUST_TRUSTED, "the decision survives");
    assert_eq!(rows[0].decided_ms, Some(2_000));

    // A decision about a publisher nobody has met is not a decision: there is no row for the installer to consult.
    assert!(!db.set_publisher_trust("@ghost", "AB12 CD34 EF56 7890", crate::TRUST_TRUSTED, 4_000).expect("updates"));
}
