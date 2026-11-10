use std::sync::Arc;
use synra_protocol::error::ErrorCode;
use super::{Server, client, get, response};

#[test]
fn a_304_is_an_answer_and_not_a_redirect() {
    // ★ A conditional request's cache hit has no `Location` and is not a redirect. Treating it as one made every cached
    // registry document a protocol violation instead of a saved round trip.
    let server = Server::always(304, "");

    let response = client().fetch(&get(&server.url("/cached"))).expect("a conditional answer");

    assert_eq!(response.status, 304);
    assert_eq!(response.body, "");
}

#[test]
fn a_redirect_to_a_granted_host_is_followed() {
    // The ordinary case: a redirect is how a great deal of the web works, so refusing all of them would be refusing the
    // feature.
    let target = Server::always(200, "arrived");
    let destination = target.url("/final");
    let location = destination.clone();
    let source = Server::start(move |_| response(302, "", &[("location", &location)]));

    let response = client().fetch(&get(&source.url("/start"))).expect("followed");

    assert_eq!(response.body, "arrived");
    // ★ The address the response came from, not the one the plugin asked for: a plugin reading `response.url` on a
    // redirect chain wants to know where it ended up.
    assert_eq!(response.url, destination);
    assert!(response.redirected, "a followed redirect is not reported");
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
