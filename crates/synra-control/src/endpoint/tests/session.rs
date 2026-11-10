use synra_protocol::error::ErrorCode;
use crate::{Request, Response};
use super::super::{Client, Listener, serve_stream};
use super::{Fake, TempDir, serve_in_background};

#[test]
fn a_client_and_a_kernel_talk_over_a_real_socket() {
    // ★ The end-to-end test, and the only one that proves the framing works on a stream that delivers partial
    // messages rather than on a buffer a test filled.
    let dir = TempDir::new("round-trip");
    let listener = Listener::bind(dir.path()).expect("binds");
    let serving = serve_in_background(listener, Fake::new());

    let mut client = Client::connect(dir.path()).expect("connects");
    let hello = client.handshake().expect("handshakes");
    match hello {
        Response::Hello { kernel, .. } => assert_eq!(kernel, "0.1.0-test"),
        other => panic!("expected a hello, got {other:?}"),
    }

    let status = client.ask(&Request::Status).expect("asks");
    assert_eq!(status, Response::ok(serde_json::json!({"kind": "status"})));

    drop(client);
    assert!(serving.join().expect("the thread finished").is_ok());
}

#[test]
fn several_requests_over_one_connection_each_get_their_own_answer() {
    // What a command-line client does when a command needs more than one question — and the property a handler that
    // answered out of order would break.
    let dir = TempDir::new("several");
    let listener = Listener::bind(dir.path()).expect("binds");
    let serving = serve_in_background(listener, Fake::new());

    let mut client = Client::connect(dir.path()).expect("connects");
    client.handshake().expect("handshakes");
    for (request, kind) in [
        (Request::Status, "status"),
        (
            Request::Devices {
                include_unpaired: true,
                scan_ms: None,
            },
            "devices",
        ),
        (Request::Plugins, "plugins"),
        (
            Request::Logs {
                lines: 5,
                verbose: false,
                trace: None,
            },
            "logs",
        ),
    ] {
        assert_eq!(
            client.ask(&request).expect("asks"),
            Response::ok(serde_json::json!({"kind": kind})),
            "{kind}"
        );
    }

    drop(client);
    assert!(serving.join().expect("the thread finished").is_ok());
}

#[test]
fn a_kernels_refusal_arrives_as_a_response_rather_than_an_error() {
    // ★ One failing command must not take the connection with it: a script that runs five commands and gets a
    // refusal for the third has to read the other four answers.
    let dir = TempDir::new("refusal");
    let listener = Listener::bind(dir.path()).expect("binds");
    let serving = serve_in_background(listener, Fake::refusing(ErrorCode::DeviceOffline));

    let mut client = Client::connect(dir.path()).expect("connects");
    client.handshake().expect("handshakes");

    let first = client.ask(&Request::Status).expect("asks");
    assert_eq!(first.error_code(), Some(ErrorCode::DeviceOffline.as_str()));
    match &first {
        Response::Failed { retryable, .. } => assert!(retryable),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And the connection still works, which is the point.
    assert!(!client.ask(&Request::Plugins).expect("asks").is_ok());

    drop(client);
    assert!(serving.join().expect("the thread finished").is_ok());
}

#[test]
fn accepting_a_connection_and_serving_it_are_separate_steps() {
    // ★ The daemon accepts on its loop thread and serves each client on its own, because a command that waits must not
    // queue every other command behind it. A `Listener` that could only do both would make that queue the design. The
    // assertion is that a request is answered across the hand-off — not merely that `accept` returns a socket.
    let dir = TempDir::new("accept-first");
    let listener = Listener::bind(dir.path()).expect("binds");

    let client = std::thread::spawn({
        let data_dir = dir.path().to_path_buf();
        move || {
            let mut client = Client::connect(&data_dir).expect("connects");
            client.handshake().expect("handshakes");
            client.ask(&Request::Status).expect("asks")
        }
    });

    let stream = listener.accept().expect("a connection");
    let server = std::thread::spawn(move || {
        let kernel = Fake::new();
        serve_stream(stream, &kernel).expect("serves");
    });

    match client.join().expect("the client finished") {
        Response::Ok { value } => assert_eq!(value["kind"], "status"),
        other => panic!("expected an answer, got {other:?}"),
    }
    server.join().expect("the server finished");
}

#[test]
fn a_client_that_disconnects_mid_batch_ends_the_connection_cleanly() {
    // The user pressed Ctrl-C. A server that treated it as an error would log a failure for every interrupted
    // command.
    let dir = TempDir::new("disconnect");
    let listener = Listener::bind(dir.path()).expect("binds");
    let serving = serve_in_background(listener, Fake::new());

    let mut client = Client::connect(dir.path()).expect("connects");
    client.handshake().expect("handshakes");
    drop(client);

    let result = serving.join().expect("the thread finished");
    assert!(
        result.is_ok(),
        "an interrupted client was reported as a failure: {result:?}"
    );
}
