use std::sync::Arc;
use synra_core::network::NetworkGuard;
use synra_core::network::IpPolicy;
use synra_protocol::error::ErrorCode;
use crate::{Client, Limits};
use super::{Server, get, local_guard, raw_server, response};

#[test]
fn the_binary_body_has_the_same_ceiling_as_a_text_one() {
    let address = raw_server(vec![7u8; 16]);
    let url = format!("http://{address}/big");
    let client = Client::new(
        NetworkGuard::for_hosts(&["127.0.0.1".to_owned()])
            .allowing_insecure(true)
            .with_policy(IpPolicy { allow_loopback: true, ..IpPolicy::default() }),
        Limits { max_response_bytes: 4, ..Limits::default() },
    );

    let refused = client.fetch_bytes(&get(&url)).expect_err("over the ceiling");

    assert_eq!(refused.code, ErrorCode::ResponseTooLarge, "{refused}");
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

    // ★ Wait for **evidence** that the slot is held, rather than for a duration that is usually long enough.
    //
    // The server answering is the proof: the slot is taken before the request is sent, so a request that arrived means the
    // count is 1. This was a fixed 200 ms sleep, and it passed alone and failed in the workspace run — where the machine is
    // compiling and testing everything at once and 200 ms is not a promise. A sleep that has to be long enough is a test
    // whose result depends on the load, which is the flakiness that teaches people to re-run rather than to read.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while server.requests() == 0 {
        assert!(std::time::Instant::now() < deadline, "the first request never reached the server");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let refused = client.fetch(&get(&server.url("/second"))).expect_err("the slot is taken");
    assert_eq!(refused.code, ErrorCode::RateLimited, "{refused}");

    // ★ And the slot is released when the first finishes, which a guard object rather than a matching decrement is what
    // makes true on the error paths too.
    *release.lock() = true;
    assert!(first.join().expect("joined").is_ok());

    let after = client.fetch(&get(&server.url("/third"))).expect("the slot came back");
    assert_eq!(after.body, "done");
}
