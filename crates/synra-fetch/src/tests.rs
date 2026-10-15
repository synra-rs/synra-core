//! The client, against a server that actually answers.
//!
//! # Why these tests open a socket
//!
//! Because everything this module decides is a decision about a request that is about to be made, and a test that stubbed
//! the transport would be testing the *stub's* idea of what the guard did. The server below is sixteen lines of
//! `TcpListener` that reads a request line and writes a response — enough to prove the request went where it was sent and
//! that the answer came back, without a dependency that would need the network to fetch.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use synra_core::network::{IpPolicy, NetworkGuard};
use synra_protocol::error::ErrorCode;

use super::{Client, Limits, Request};

/// What the test server answers with.
type Reply = Box<dyn Fn(&str) -> String + Send + Sync>;

/// A server on a loopback port, and its address.
///
/// The handler is given the request's first line — `GET /path HTTP/1.1` — and returns the whole response, so a test can
/// answer differently per path and can issue redirects.
struct Server {
    /// Where it is listening.
    address: SocketAddr,
    /// How many requests it has answered.
    served: Arc<AtomicUsize>,
}

impl Server {
    fn start(reply: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a port");
        let address = listener.local_addr().expect("an address");
        let served = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&served);
        let reply: Reply = Box::new(reply);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let _ = counted.fetch_add(1, Ordering::Relaxed);
                let first = read_request_line(&stream);
                let response = reply(&first);
                let mut stream = stream;
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Self { address, served }
    }

    /// A server that answers `body` with `status` for every request.
    fn always(status: u16, body: &str) -> Self {
        let body = body.to_owned();
        Self::start(move |_| response(status, &body, &[]))
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn requests(&self) -> usize {
        self.served.load(Ordering::Relaxed)
    }
}

/// Reads up to the blank line, and returns the request line.
fn read_request_line(stream: &TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    let _ = reader.read_line(&mut first);
    // Drain the headers, so the client is not left writing into a socket nobody reads.
    let mut line = String::new();
    while let Ok(read) = reader.read_line(&mut line) {
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }
    first.trim_end().to_owned()
}

/// A whole HTTP response.
fn response(status: u16, body: &str, extra: &[(&str, &str)]) -> String {
    let reason = if (300..400).contains(&status) { "Found" } else { "OK" };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    head.push_str(body);
    head
}

/// A guard that reaches the test's own server: loopback, and plain http.
///
/// # Why the test grants what the product refuses
///
/// Because the product's defaults are the thing being tested elsewhere — `synra-core`'s guard tests assert that loopback
/// and `http` are refused. What these tests are about is the *client*: that a request goes where it was sent, that a
/// redirect is re-validated, that the body limit is applied. So the guard is configured for the test and says so, rather
/// than the test pretending the defaults are different.
fn local_guard() -> NetworkGuard {
    NetworkGuard::for_hosts(&["127.0.0.1".to_owned()])
        .allowing_insecure(true)
        .with_policy(IpPolicy { allow_loopback: true, ..IpPolicy::default() })
}

fn client() -> Client {
    Client::new(local_guard(), Limits::default())
}

fn get(url: &str) -> Request {
    Request {
        url: url.to_owned(),
        method: "GET".to_owned(),
        headers: std::collections::BTreeMap::new(),
        body: None,
    }
}

#[test]
fn a_request_reaches_the_server_and_the_answer_comes_back() {
    // The base case, and the one that proves the resolver did not send the request somewhere else: the server has to have
    // seen it, and the body has to match what it wrote.
    let server = Server::always(200, "hello");

    let response = client().fetch(&get(&server.url("/greeting"))).expect("fetched");

    assert_eq!(response.status, 200);
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
fn the_guard_runs_before_the_request_is_made() {
    // ★ The property that makes the guard worth having: a refused URL costs no connection at all. A check made after the
    // bytes were sent would be a report rather than a policy.
    let server = Server::always(200, "hello");
    let client = Client::new(
        NetworkGuard::for_hosts(&["somewhere-else.example".to_owned()]).allowing_insecure(true),
        Limits::default(),
    );

    let refused = client.fetch(&get(&server.url("/"))).expect_err("not granted");

    assert_eq!(refused.code, ErrorCode::HostNotAllowed, "{refused}");
    assert_eq!(server.requests(), 0, "nothing was sent");
}

#[test]
fn a_redirect_to_a_granted_host_is_followed() {
    // The ordinary case: a redirect is how a great deal of the web works, so refusing all of them would be refusing the
    // feature.
    let target = Server::always(200, "arrived");
    let destination = target.url("/final");
    let source = Server::start(move |_| response(302, "", &[("location", &destination)]));

    let response = client().fetch(&get(&source.url("/start"))).expect("followed");

    assert_eq!(response.body, "arrived");
    assert_eq!(source.requests(), 1);
    assert_eq!(target.requests(), 1);
}

#[test]
fn a_redirect_to_a_host_nobody_granted_is_refused_at_that_hop() {
    // ★ The reason redirects are followed here rather than by the client. A granted host that redirects to an ungranted one
    // is exactly how a granted host is used to reach somewhere else, and an HTTP client following its own redirects offers
    // no moment at which that can be refused.
    let elsewhere = Server::always(200, "reached the wrong machine");
    // ★ The destination names a **different host**, not a different port.
    //
    // The first version of this test redirected to the same `127.0.0.1` on another port, and it passed the guard — because
    // a capability grants a *host*, as its spelling says (`network:fetch:<host>`), and a port is not part of that grant.
    // That is the contract, so the test was wrong rather than the guard; `localhost` is the same machine under a name
    // nobody granted, which is exactly the case that must be refused.
    let destination = format!("http://localhost:{}/final", elsewhere.address.port());
    let source = Server::start(move |_| response(302, "", &[("location", &destination)]));

    let refused = client().fetch(&get(&source.url("/start"))).expect_err("the second hop is not granted");

    assert_eq!(refused.code, ErrorCode::HostNotAllowed, "{refused}");
    assert_eq!(elsewhere.requests(), 0, "the second hop was never made");
    // And the port is not the grant: the same host on another port *is* reachable, because the capability names a host.
    // Asserted rather than left implicit, so that a future change to include ports has to change this test and the
    // contract's spelling together.
    assert!(client().fetch(&get(&elsewhere.url("/same-host"))).is_ok(), "the granted host, another port");
}

#[test]
fn a_redirect_with_no_location_is_a_protocol_failure_rather_than_a_guess() {
    let server = Server::start(|_| response(302, "", &[]));

    let refused = client().fetch(&get(&server.url("/"))).expect_err("nowhere to follow");

    assert_eq!(refused.code, ErrorCode::ProtocolViolation, "{refused}");
}

#[test]
fn redirects_stop_at_the_limit() {
    // A server that redirects to itself for ever. The limit is what stops it, and the refusal says which limit.
    let address = Arc::new(parking_lot::Mutex::new(String::new()));
    let looped = Arc::clone(&address);
    let server = Server::start(move |_| {
        let url = looped.lock().clone();
        response(302, "", &[("location", &url)])
    });
    *address.lock() = server.url("/again");

    let refused = client().fetch(&get(&server.url("/"))).expect_err("too many hops");

    assert_eq!(refused.code, ErrorCode::RedirectBlocked, "{refused}");
    // Five redirects are followed, so the server sees the first request plus five hops.
    assert_eq!(server.requests(), 6, "and it stopped rather than looping");
}

#[test]
fn a_body_larger_than_the_limit_is_refused_rather_than_read() {
    // ★ The limit is applied **at the read**, not after it: a check made once the bytes are in memory is a check that has
    // already been exceeded — the shape of enforcement that does not enforce anything.
    let server = Server::always(200, &"x".repeat(64));
    let client = Client::new(local_guard(), Limits { max_response_bytes: 16, ..Limits::default() });

    let refused = client.fetch(&get(&server.url("/big"))).expect_err("too large");

    assert_eq!(refused.code, ErrorCode::ResponseTooLarge, "{refused}");
}

#[test]
fn a_body_within_the_limit_is_read_whole() {
    // The other half, so the test above cannot pass by refusing everything.
    let payload = "x".repeat(16);
    let server = Server::always(200, &payload);
    let client = Client::new(local_guard(), Limits { max_response_bytes: 16, ..Limits::default() });

    let response = client.fetch(&get(&server.url("/exact"))).expect("exactly at the limit");

    assert_eq!(response.body.len(), 16);
}

#[test]
fn a_request_body_larger_than_the_limit_is_refused_before_a_slot_is_taken() {
    // A cheap refusal must not consume a concurrency slot, or a plugin sending rubbish would exhaust its own budget with
    // work it never started.
    let server = Server::always(200, "ok");
    let client = Client::new(local_guard(), Limits { max_request_bytes: 4, ..Limits::default() });
    let mut request = get(&server.url("/"));
    request.method = "POST".to_owned();
    request.body = Some("far too long".to_owned());

    let refused = client.fetch(&request).expect_err("too large");

    assert_eq!(refused.code, ErrorCode::PayloadTooLarge, "{refused}");
    assert_eq!(server.requests(), 0);
}

#[test]
fn a_plugin_may_have_only_so_many_requests_in_flight() {
    // The server holds the first request open until the second has been attempted, so the limit is reached deterministically
    // rather than by racing two threads.
    let release = Arc::new(parking_lot::Mutex::new(false));
    let held = Arc::clone(&release);
    let server = Server::start(move |_| {
        // Wait for the test to let go.
        while !*held.lock() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        response(200, "done", &[])
    });

    let client = Arc::new(Client::new(local_guard(), Limits { max_concurrent: 1, ..Limits::default() }));
    let url = server.url("/held");

    let first = {
        let client = Arc::clone(&client);
        std::thread::spawn(move || client.fetch(&get(&url)))
    };

    // Give the first request time to take the slot.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let refused = client.fetch(&get(&server.url("/second"))).expect_err("the slot is taken");
    assert_eq!(refused.code, ErrorCode::RateLimited, "{refused}");

    // ★ And the slot is released when the first finishes, which a guard object rather than a matching decrement is what
    // makes true on the error paths too.
    *release.lock() = true;
    assert!(first.join().expect("joined").is_ok());

    let after = client.fetch(&get(&server.url("/third"))).expect("the slot came back");
    assert_eq!(after.body, "done");
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

    let response = super::Response {
        status: 200,
        headers: std::collections::BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: "{}".to_owned(),
    };
    let json = serde_json::to_value(&response).expect("serialises");

    assert_eq!(json["status"], 200);
    assert_eq!(json["headers"]["content-type"], "application/json");
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
