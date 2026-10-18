//! Answering "what plugins do you have" from this device's own tables.
//!
//! # Why these are integration tests
//!
//! Because the answer is a join: `plugins` says what is installed and enabled, `plugin_versions` says which version is in
//! effect, and neither table alone is the list a peer asked for. The request/response envelopes have their own tests in
//! `plugin_list_exchange.rs`; what is tested here is the half that turns a store into that answer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_core::messaging::plugin_list_request;
use synra_core::plugin_sync::{answer_plugin_list, local_list};
use synra_protocol::ids::{DeviceId, TraceId};
use synra_protocol::session::PluginList;
use synra_store::SynraDb;

/// A database holding one installed plugin with an active version.
fn with_a_plugin(version: &str, digest: &str, enabled: bool) -> SynraDb {
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", enabled, true, "installed", 1_000, 1_000)
        .expect("a plugin");
    db.record_plugin_version("@acme/hello", version, "plugin.wasm", digest, "{}", 1_000)
        .expect("a version");
    db
}

#[test]
fn the_list_is_built_from_the_active_version_and_the_enabled_flag() {
    let db = with_a_plugin("1.2.3", "sha256-abc", true);

    let list = local_list(&db).expect("a list");

    assert_eq!(list.plugins.len(), 1);
    let summary = &list.plugins[0];
    assert_eq!(summary.plugin_id.as_str(), "@acme/hello");
    assert_eq!(summary.version.as_deref(), Some("1.2.3"));
    assert_eq!(summary.digest.as_deref(), Some("sha256-abc"));
    assert!(summary.active, "enabled is what the store knows about active");
}

#[test]
fn a_plugin_without_an_active_version_is_not_offered() {
    // ★ The join, and the failure it guards: a row in `plugins` with no active row in `plugin_versions` has no artifact to
    // describe. Reporting it with a made-up version would tell a peer to skip a transfer for bytes this device does not have.
    let mut db = SynraDb::open_in_memory().expect("an in-memory database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/hello", true, true, "installed", 1_000, 1_000)
        .expect("a plugin");

    let list = local_list(&db).expect("a list");

    assert!(list.plugins.is_empty(), "nothing to offer: {:?}", list.plugins);
}

#[test]
fn a_disabled_plugin_is_still_listed() {
    // "Do you have it" is about the bytes, not about whether it may run: a device that hid a disabled plugin would make the
    // peer plan to send it again, and the transfer would replace a version the user deliberately switched off.
    let db = with_a_plugin("1.2.3", "sha256-abc", false);

    let list = local_list(&db).expect("a list");

    assert_eq!(list.plugins.len(), 1);
    assert!(!list.plugins[0].active);
}

#[test]
fn the_answer_replies_to_the_question_and_carries_the_list() {
    let db = with_a_plugin("1.2.3", "sha256-abc", true);
    let asker = DeviceId::new();
    let answerer = DeviceId::new();
    let request = plugin_list_request(asker, answerer, TraceId::new(), 1_000).expect("a request");

    let response = answer_plugin_list(&db, &request, answerer, 1_100).expect("an answer");

    // Through the wire form, because that is what the peer reads.
    let asked = serde_json::to_value(&request).expect("the request");
    let answered = serde_json::to_value(&response).expect("the answer");
    assert_eq!(answered["replyTo"], asked["requestId"], "the answer names the question");
    let decoded: PluginList = serde_json::from_value(answered["payload"].clone()).expect("it decodes");
    assert_eq!(decoded, local_list(&db).expect("the same list"));
}
