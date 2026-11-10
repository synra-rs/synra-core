use synra_core::network::NetworkGuard;
use synra_core::network::IpPolicy;
use synra_protocol::error::ErrorCode;
use crate::{Client, Limits};
use super::{Server, client, get, response};

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
fn authorized_fetch_scopes_are_rechecked_for_the_method_of_every_redirect() {
    let destination = Server::always(200, "allowed");
    let target = destination.url("/final").replace("127.0.0.1", "localhost");
    let source = Server::start(move |_| response(302, "", &[("location", &target)]));
    let client = Client::new(
        NetworkGuard::for_hosts(&["127.0.0.1".to_owned(), "localhost".to_owned()])
            .allowing_insecure(true)
            .with_policy(IpPolicy {
                allow_loopback: true,
                ..IpPolicy::default()
            }),
        Limits::default(),
    );
    let mut request = get(&source.url("/start"));
    request.method = "POST".to_owned();
    let grants = [
        "network:fetch:127.0.0.1:POST".to_owned(),
        "network:fetch:localhost:GET".to_owned(),
    ];
    let denied = client.fetch_authorized(&request, &grants).unwrap_err();
    assert_eq!(denied.code, ErrorCode::CapabilityDenied, "{denied}");
    assert_eq!(source.requests(), 1);
    assert_eq!(destination.requests(), 0);
    let grants = [
        "network:fetch:127.0.0.1:POST".to_owned(),
        "network:fetch:localhost:POST".to_owned(),
    ];
    assert_eq!(
        client.fetch_authorized(&request, &grants).unwrap().body,
        "allowed"
    );
    assert_eq!(destination.requests(), 1);
}

#[test]
fn authorized_fetch_does_not_keep_revoked_or_changed_method_grants_in_the_client() {
    let server = Server::always(200, "yes");
    let client = client();
    let mut request = get(&server.url("/"));
    let read = ["network:fetch:127.0.0.1:GET".to_owned()];
    assert!(client.fetch_authorized(&request, &read).is_ok());
    assert_eq!(
        client.fetch_authorized(&request, &[]).unwrap_err().code,
        ErrorCode::CapabilityDenied
    );
    let write = ["network:fetch:127.0.0.1:POST".to_owned()];
    assert_eq!(
        client.fetch_authorized(&request, &write).unwrap_err().code,
        ErrorCode::CapabilityDenied
    );
    assert_eq!(server.requests(), 1);
    request.method = "POST".to_owned();
    assert!(client.fetch_authorized(&request, &write).is_ok());
    assert_eq!(server.requests(), 2);
}

#[test]
fn authorized_fetch_refuses_a_malformed_stored_grant_without_partial_authority() {
    let server = Server::always(200, "no");
    let grants = [
        "network:fetch:127.0.0.1".to_owned(),
        "not-a-capability".to_owned(),
    ];
    let error = client()
        .fetch_authorized(&get(&server.url("/")), &grants)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
    assert_eq!(server.requests(), 0);
}
