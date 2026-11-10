use synra_core::network::NetworkGuard;
use crate::{Client, Limits, Request, Response};
use super::{Server, client, get, raw_server, response};

#[test]
fn a_binary_body_comes_back_unchanged() {
    // ★ The reason this entry point exists: a registry tarball is not UTF-8, and decoding it as text would corrupt it
    // before the signature could check it (16 §4.1).
    let bytes = vec![0x00, 0xFF, 0xFE, b'P', b'K', 0x03, 0x04];
    let address = raw_server(bytes.clone());
    let url = format!("http://{address}/package.synra");

    let response = client().fetch_bytes(&get(&url)).expect("fetched");

    assert_eq!(response.status, 200);
    assert_eq!(response.url, url);
    assert_eq!(response.body, bytes, "the bytes were altered on the way back");
}

#[test]
fn a_request_reaches_the_server_and_the_answer_comes_back() {
    // The base case, and the one that proves the resolver did not send the request somewhere else: the server has to have
    // seen it, and the body has to match what it wrote.
    let server = Server::always(200, "hello");

    let response = client().fetch(&get(&server.url("/greeting"))).expect("fetched");

    assert_eq!(response.status, 200);
    assert_eq!(response.status_text, "OK", "the reason phrase is missing");
    assert_eq!(response.url, server.url("/greeting"), "the response names another address");
    assert!(!response.redirected, "a direct answer claims a redirect");
    assert_eq!(response.body, "hello");
    assert_eq!(server.requests(), 1, "the server answered exactly one request");
}

#[test]
fn a_status_is_an_answer_rather_than_a_failure() {
    // ★ A plugin asking about something that is not there has to be able to read the status and the body. A client that
    // turned 404 into `Err` would take that away, and the plugin would have no way to tell "no such thing" from "the
    // network is down".
    let server = Server::always(404, "not here");

    let response = client().fetch(&get(&server.url("/missing"))).expect("an answer, not a failure");

    assert_eq!(response.status, 404);
    assert_eq!(response.body, "not here");
}

#[test]
fn a_method_that_is_not_a_read_sends_its_body() {
    // The server answers with the request line, so the test can see the method the client actually sent.
    let server = Server::start(|line| response(200, line, &[]));
    let mut request = get(&server.url("/submit"));
    request.method = "POST".to_owned();
    request.body = Some("{\"a\":1}".to_owned());

    let response = client().fetch(&request).expect("posted");

    assert!(response.body.starts_with("POST /submit"), "{}", response.body);
}

#[test]
fn a_request_naming_no_method_is_a_read() {
    // The default, which the contract offers: a request that names none is a read rather than a guess.
    let request: Request =
        serde_json::from_str(r#"{"url":"http://127.0.0.1:1/"}"#).expect("a request with no method");

    assert_eq!(request.method, "GET");
    assert!(request.body.is_none());
}

#[test]
fn the_shapes_a_plugin_sends_and_receives_are_the_documented_ones() {
    // The payload shape is not in the design documents, so it is decided in this module's docs — and asserted here, so
    // that a rename cannot quietly change what a plugin has to write.
    let request: Request = serde_json::from_str(
        r#"{"url":"https://api.example.com/v1","method":"POST","headers":{"accept":"application/json"},"body":"{}"}"#,
    )
    .expect("the documented request");

    assert_eq!(request.url, "https://api.example.com/v1");
    assert_eq!(request.method, "POST");
    assert_eq!(request.headers.get("accept").map(String::as_str), Some("application/json"));
    assert_eq!(request.body.as_deref(), Some("{}"));

    let response = Response {
        status: 200,
        status_text: "OK".to_owned(),
        headers: std::collections::BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        url: "https://api.example.com/v1".to_owned(),
        redirected: false,
        body: "{}".to_owned(),
    };
    let json = serde_json::to_value(&response).expect("serialises");

    assert_eq!(json["status"], 200);
    assert_eq!(json["statusText"], "OK");
    assert_eq!(json["headers"]["content-type"], "application/json");
    assert_eq!(json["url"], "https://api.example.com/v1");
    assert_eq!(json["redirected"], false);
    assert_eq!(json["body"], "{}");
}

#[test]
fn an_empty_method_is_refused_rather_than_defaulted() {
    // `""` is a plugin that meant to name a method and did not. Defaulting it to `GET` would send a read where something
    // else was intended, and the plugin would have no way to notice.
    let server = Server::always(200, "ok");
    let mut request = get(&server.url("/"));
    request.method = String::new();

    assert!(client().fetch(&request).is_err());
    assert_eq!(server.requests(), 0);
}

#[test]
fn a_fetch_that_panics_inside_the_client_is_a_refusal() {
    // ★ A server must not be able to kill the host by answering with something the client mishandles.
    //
    // `ureq-proto` 0.6.4 panics when a response carries more of a particular thing than its `ArrayVec<_, 16>` holds. This
    // test was written as a probe after the daemon's catalogue command panicked through it: an **unresolvable** host errors
    // cleanly, and a resolvable one reaches the bug — which is why nothing in this crate's own suite saw it, since every
    // other test talks to a `127.0.0.1` fixture this process writes.
    //
    // What the test asserts is deliberately weak about the network and strict about the panic: whether the request fails or
    // succeeds depends on the machine, and **neither may be a panic**. On a host with no resolver this is an ordinary `Err`,
    // and on the machine where this was found it is the wrapped panic.
    let guard = NetworkGuard::for_hosts(&["registry.npmjs.org".to_owned()]);
    let client = Client::new(guard, Limits::default());
    let request = Request {
        method: "GET".to_owned(),
        url: "https://registry.npmjs.org/%40acme/chat".to_owned(),
        headers: std::collections::BTreeMap::new(),
        body: None,
    };

    // Before the fix this line panicked the test process. It now returns, whatever the network did.
    let outcome = client.fetch(&request);
    if let Err(refusal) = &outcome {
        // A wrapped panic says so, so the next reader is not sent looking at the network.
        assert!(
            !refusal.message.contains("panicked") || refusal.message.contains("HTTP client"),
            "{refusal:?}"
        );
    }
}
