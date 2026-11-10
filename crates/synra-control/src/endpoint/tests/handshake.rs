use synra_protocol::error::ErrorCode;
use crate::Request;
use super::super::{Client, Listener};
use super::{Fake, TempDir, serve_in_background};

#[test]
fn a_client_that_never_handshakes_is_refused() {
    // ★ The handshake is what establishes the version, and a server that served a request without one would be
    // answering a protocol it never agreed to.
    let dir = TempDir::new("no-handshake");
    let listener = Listener::bind(dir.path()).expect("binds");
    let serving = serve_in_background(listener, Fake::new());

    let mut client = Client::connect(dir.path()).expect("connects");
    let response = client.ask(&Request::Status).expect("asks");
    assert_eq!(
        response.error_code(),
        Some(ErrorCode::InvalidArgument.as_str())
    );

    drop(client);
    assert!(serving.join().expect("the thread finished").is_ok());
}

#[test]
fn a_version_the_kernel_does_not_speak_ends_the_connection() {
    let dir = TempDir::new("version");
    let listener = Listener::bind(dir.path()).expect("binds");
    let serving = serve_in_background(listener, Fake::new());

    let mut client = Client::connect(dir.path()).expect("connects");
    let response = client
        .ask(&Request::Hello {
            version: crate::PROTOCOL_VERSION + 1,
        })
        .expect("asks");
    assert_eq!(
        response.error_code(),
        Some(ErrorCode::ProtocolVersionUnsupported.as_str())
    );

    // The server closed, so the next question finds a closed stream rather than a second refusal.
    assert!(client.ask(&Request::Status).is_err());

    drop(client);
    assert!(serving.join().expect("the thread finished").is_ok());
}
