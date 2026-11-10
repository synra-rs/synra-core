use crate::MAX_MESSAGE_LEN;

use super::*;

#[test]
fn a_pipelined_batch_is_answered_in_order() {
    // ★ Answers are appended in the order the requests arrived, one per request. A client that pipelined three reads
    // three positionally, so a handler that answered out of order would make a script read the status report as the
    // device list.
    let kernel = Fake::ok();
    let mut server = Server::new();
    let mut input = Vec::new();
    for request in [hello(), Request::Status, Request::Plugins] {
        input.extend_from_slice(&crate::encode(&request).expect("encodes"));
    }
    let mut out = Vec::new();
    server.feed(&input, &kernel, &mut out).expect("no error");

    let mut decoder = Decoder::new();
    decoder.push(&out);
    let first: Response = decoder.next_message().expect("no error").expect("one");
    let second: Response = decoder.next_message().expect("no error").expect("two");
    let third: Response = decoder.next_message().expect("no error").expect("three");
    assert!(matches!(first, Response::Hello { .. }));
    assert_eq!(
        second,
        Response::ok(serde_json::json!({"state": "running"}))
    );
    assert_eq!(third, Response::ok(serde_json::json!({"plugins": []})));
    assert_eq!(server.answered(), 3);
}

#[test]
fn a_partial_request_produces_no_answer_yet() {
    // A socket delivers bytes, not messages. A handler that answered a half-arrived request would answer something
    // nobody asked.
    let kernel = Fake::ok();
    let mut server = Server::new();
    let bytes = crate::encode(&hello()).expect("encodes");
    let mut out = Vec::new();
    let state = server
        .feed(&bytes[..bytes.len() - 1], &kernel, &mut out)
        .expect("no error");

    assert_eq!(state, SessionState::Open);
    assert!(out.is_empty(), "answered a partial request");
    assert_eq!(server.answered(), 0);
}

#[test]
fn a_request_split_across_reads_is_answered_once() {
    let kernel = Fake::ok();
    let mut server = Server::new();
    let bytes = crate::encode(&hello()).expect("encodes");
    let mut out = Vec::new();

    let split = bytes.len() / 2;
    server
        .feed(&bytes[..split], &kernel, &mut out)
        .expect("no error");
    assert!(out.is_empty());
    server
        .feed(&bytes[split..], &kernel, &mut out)
        .expect("no error");

    assert_eq!(server.answered(), 1);
    let mut decoder = Decoder::new();
    decoder.push(&out);
    assert!(matches!(
        decoder.next_message::<Response>().expect("no error"),
        Some(Response::Hello { .. })
    ));
}

#[test]
fn an_oversized_length_is_a_framing_error_the_caller_closes_on() {
    // The ceiling is enforced by the decoder, and the handler propagates it rather than swallowing it: a caller that
    // continued after this would be reading a stream whose position nobody can vouch for.
    let kernel = Fake::ok();
    let mut server = Server::new();
    let mut input = Vec::new();
    let huge = u32::try_from(MAX_MESSAGE_LEN + 1).expect("fits");
    input.extend_from_slice(&huge.to_be_bytes());

    let mut out = Vec::new();
    assert!(server.feed(&input, &kernel, &mut out).is_err());
    assert!(out.is_empty());
}

#[test]
fn a_malformed_body_is_a_framing_error_and_nothing_is_answered() {
    let kernel = Fake::ok();
    let mut server = Server::new();
    let body = b"{not json";
    let mut input = Vec::new();
    input.extend_from_slice(&u32::try_from(body.len()).expect("fits").to_be_bytes());
    input.extend_from_slice(body);

    let mut out = Vec::new();
    assert!(server.feed(&input, &kernel, &mut out).is_err());
    assert!(out.is_empty());
}
