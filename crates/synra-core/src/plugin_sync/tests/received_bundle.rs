use synra_protocol::ids::{DeviceId, TransferId};

use super::super::*;
use super::plugin;

/// A migrated database for one received bundle.
fn received_db() -> synra_store::SynraDb {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db
}

/// A finished transfer carrying a bundle for `@acme/chat`.
fn received_bundle(version: Option<&str>) -> crate::listener::FinishedTransfer {
    crate::listener::FinishedTransfer {
        transfer_id: Some(TransferId::new()),
        path: std::path::PathBuf::from("inbox/plugin-acme-chat.wasm"),
        byte_length: 4_096,
        bundle: Some(plugin("@acme/chat")),
        peer: DeviceId::new(),
        digest: "sha256-test".to_owned(),
        version: version.map(str::to_owned),
        sync_session_id: None,
    }
}

#[test]
fn a_received_bundle_becomes_history_and_what_the_peer_holds() {
    // The two answers are different questions: the history says what happened, and `sync_records` says what the peer holds
    // now. Until this function existed, only the first had a writer in either host.
    let db = received_db();
    let transfer = received_bundle(Some("1.2.0"));

    let outcome = record_received(&db, &transfer).expect("a bundle has an outcome");

    let history = db.sync_log(None, 10).expect("reads");
    assert_eq!(history.len(), 1, "the bundle was not recorded: {history:?}");
    assert_eq!(history[0].plugin_id, "@acme/chat");
    assert_eq!(history[0].peer_device, transfer.peer.to_string());
    assert!(
        history[0].finished_at_ms.is_some(),
        "a finished transfer with no end time"
    );

    let held = db.sync_records().expect("reads");
    assert_eq!(
        held.len(),
        1,
        "what the peer holds was not recorded: {held:?}"
    );
    assert_eq!(
        held[0].version, "1.2.0",
        "the version travelled with the transfer"
    );
    assert_eq!(held[0].digest, "sha256-test");

    assert!(outcome.installed);
    assert_eq!(outcome.installed_version.as_deref(), Some("1.2.0"));
}

#[test]
fn an_attachment_is_not_a_synchronisation() {
    // A screenshot is not a sync. A history full of them would answer "what has been synced" with rows that were files.
    let db = received_db();
    let mut attachment = received_bundle(None);
    attachment.bundle = None;

    assert!(record_received(&db, &attachment).is_none());
    assert!(db.sync_log(None, 10).expect("reads").is_empty());
    assert!(db.sync_records().expect("reads").is_empty());
    assert!(
        db.plugins().expect("reads").is_empty(),
        "an attachment installed a plugin"
    );
}

#[test]
fn a_received_bundle_is_installed_enabled_and_untrusted() {
    let db = received_db();

    let outcome = record_received(&db, &received_bundle(Some("1.2.0"))).expect("an outcome");

    let installed = db.plugins().expect("reads");
    assert_eq!(installed.len(), 1, "{installed:?}");
    assert!(installed[0].enabled, "the row says it may run");
    assert!(
        !installed[0].trusted,
        "a file that just arrived has been confirmed by nobody"
    );
    assert_eq!(
        installed[0].health, "unknown",
        "health is observed, not assumed"
    );
    // ★ The outcome has to agree with the row it just wrote: it used to say `activated: false` because the check that
    // would set it required a `SessionComplete` the transfer path never performs — while the row beside it was enabled.
    assert!(
        outcome.activated,
        "the outcome contradicts the row it wrote"
    );
}

#[test]
fn the_outcome_claims_no_receiver_check_was_performed() {
    // The honest half: a bundle was installed, and the seven duties of ⑧ were **not** run on this path. An outcome that
    // listed them would make the sender's history describe work nobody did.
    let db = received_db();

    let outcome = record_received(&db, &received_bundle(Some("1.2.0"))).expect("an outcome");

    assert!(
        outcome.performed.is_empty(),
        "checks that did not run were reported: {:?}",
        outcome.performed
    );
    assert!(
        !outcome.is_fully_checked(),
        "an install is not a fully checked sync"
    );
    assert!(outcome.error.is_none());
}
