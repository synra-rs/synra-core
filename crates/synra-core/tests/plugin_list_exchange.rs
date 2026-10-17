//! Asking a peer what it has, and reading the answer back.
//!
//! # Why these are integration tests
//!
//! Because they exercise the pair the way the kernel does: a request built here, an answer built from it, and the answer decoded
//! back into the list a plan is computed from. A test inside `messaging.rs` could build both and never check that the second is
//! a reply to the first — which is the only thing that makes the exchange work on a real link.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_core::messaging::{plugin_list_request, plugin_list_response};
use synra_protocol::ids::{DeviceId, PluginId, TraceId};
use synra_protocol::session::{PluginList, PluginSummary};

fn device() -> DeviceId {
    DeviceId::new()
}

fn list() -> PluginList {
    PluginList {
        plugins: vec![PluginSummary {
            plugin_id: PluginId::parse("@acme/hello").expect("an id"),
            version: Some("1.2.3".to_owned()),
            digest: Some("sha256-abc".to_owned()),
            active: true,
        }],
    }
}

#[test]
fn the_answer_is_a_reply_to_the_question() {
    // ★ The property a real link depends on: the answer carries the request's id, so the dialer can tell which of its questions
    // this answers. Two devices may have several conversations at once, and an answer nobody can correlate is one the asker
    // waits out its own deadline for.
    let asker = device();
    let answerer = device();
    let request = plugin_list_request(asker, answerer, TraceId::new(), 1_000).expect("a request");

    let response = plugin_list_response(&request, answerer, &list(), 1_100).expect("an answer");

    // Read through the wire form rather than through accessors: the fields a peer actually sees are the JSON ones, and a
    // getter that happened to normalise something would hide the difference.
    let sent = serde_json::to_value(&request).expect("the request");
    let answered = serde_json::to_value(&response).expect("the answer");
    assert_eq!(answered["replyTo"], sent["requestId"], "the answer names the question it answers");
    assert_eq!(answered["from"], sent["target"], "the answer comes from the device that was asked");
    assert_eq!(answered["target"], sent["from"], "and goes back to the asker");
}

#[test]
fn the_answer_carries_the_list_a_plan_is_computed_from() {
    let asker = device();
    let answerer = device();
    let request = plugin_list_request(asker, answerer, TraceId::new(), 1_000).expect("a request");
    let response = plugin_list_response(&request, answerer, &list(), 1_100).expect("an answer");

    let answered = serde_json::to_value(&response).expect("the answer");
    let decoded: PluginList = serde_json::from_value(answered["payload"].clone()).expect("it decodes");

    assert_eq!(decoded, list(), "what was sent is what is read");
}

#[test]
fn a_request_for_a_list_says_nothing_itself() {
    // The question has one form, so it carries no payload: an empty body is what the answering side reads as "the whole list".
    let request = plugin_list_request(device(), device(), TraceId::new(), 0).expect("a request");

    let sent = serde_json::to_value(&request).expect("the request");
    assert_eq!(sent["event"], "_synra.plugin.list.request");
    assert!(sent.get("payload").is_none(), "the question has no body: {sent}");
}
