use super::*;

#[test]
fn a_hello_is_answered_with_the_versions() {
    let (responses, state) = run(&Fake::ok(), &[hello()]);
    assert_eq!(state, SessionState::Open);
    match &responses[0] {
        Response::Hello { version, kernel } => {
            assert_eq!(*version, PROTOCOL_VERSION);
            assert_eq!(kernel, "0.1.0-test");
        }
        other => panic!("expected a hello, got {other:?}"),
    }
}

#[test]
fn a_mismatched_version_is_refused_and_the_connection_closes() {
    // ★ A client and a kernel are separate binaries that may be upgraded separately. Once the versions disagree
    // there is nothing to say, so the connection ends rather than answering every further request with the same
    // refusal — and the client learns both versions from the one answer.
    let (responses, state) = run(&Fake::ok(), &[Request::Hello { version: 99 }]);
    assert_eq!(state, SessionState::Close);
    assert_eq!(
        responses[0].error_code(),
        Some("protocol_version_unsupported")
    );
    match &responses[0] {
        Response::Failed { message, .. } => {
            assert!(message.contains("99"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_request_before_the_handshake_is_refused() {
    // ★ A kernel that served it would be one whose behaviour depends on a version it never established — and the
    // client would be reading answers to a protocol it never agreed to.
    let (responses, state) = run(&Fake::ok(), &[Request::Status]);
    assert_eq!(state, SessionState::Open);
    assert_eq!(responses[0].error_code(), Some("invalid_argument"));
    match &responses[0] {
        Response::Failed { message, .. } => assert!(message.contains("Hello"), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_handshake_opens_the_connection_for_what_follows() {
    let (responses, _) = run(&Fake::ok(), &[hello(), Request::Status, Request::Plugins]);
    assert_eq!(responses.len(), 3);
    assert!(matches!(responses[0], Response::Hello { .. }));
    assert!(responses[1].is_ok());
    assert!(responses[2].is_ok());
}

#[test]
fn a_second_hello_is_answered_rather_than_refused() {
    // A client that re-sends the handshake — a retry after a half-open connection — gets the same answer rather
    // than an error, because the request is well-formed and the kernel knows its own version.
    let (responses, state) = run(&Fake::ok(), &[hello(), hello(), Request::Status]);
    assert_eq!(state, SessionState::Open);
    assert!(matches!(responses[0], Response::Hello { .. }));
    assert!(matches!(responses[1], Response::Hello { .. }));
    assert!(responses[2].is_ok());
}

#[test]
fn a_failed_handshake_does_not_open_the_connection() {
    // The version check failed, so `handshook` stays false. A handler that set it anyway would serve requests over a
    // protocol mismatch — the one thing the handshake exists to prevent.
    let mut server = Server::new();
    let kernel = Fake::ok();
    let mut out = Vec::new();
    server
        .feed(
            &crate::encode(&Request::Hello { version: 99 }).expect("encodes"),
            &kernel,
            &mut out,
        )
        .expect("no framing error");
    assert!(!server.handshook());
}

#[test]
fn a_request_after_a_version_mismatch_is_not_answered() {
    // ★ The rest of the buffer is dropped. Answering it would be answering a client that has already been told to go
    // away — and the answers would be read by a client that has stopped reading.
    let kernel = Fake::ok();
    let mut server = Server::new();
    let mut input = Vec::new();
    for request in [Request::Hello { version: 99 }, Request::Status] {
        input.extend_from_slice(&crate::encode(&request).expect("encodes"));
    }
    let mut out = Vec::new();
    let state = server.feed(&input, &kernel, &mut out).expect("no error");

    assert_eq!(state, SessionState::Close);
    assert_eq!(server.answered(), 1, "answered a request after closing");
    let mut decoder = Decoder::new();
    decoder.push(&out);
    assert!(
        decoder
            .next_message::<Response>()
            .expect("no error")
            .is_some()
    );
    assert!(
        decoder
            .next_message::<Response>()
            .expect("no error")
            .is_none()
    );
}

#[test]
fn a_new_handler_starts_unhandshook_and_has_answered_nothing() {
    // The state is per connection, so a second client's handshake cannot satisfy the first's.
    let server = Server::new();
    assert!(!server.handshook());
    assert_eq!(server.answered(), 0);
    assert!(!Server::default().handshook());
}

#[test]
fn one_clients_handshake_does_not_open_another_connection() {
    // ★ The state is per connection. A kernel with one shared flag would let any client that said hello open the
    // door for every other — and the version check would then be something a client could skip by waiting.
    let kernel = Fake::ok();
    let mut first = Server::new();
    let mut out = Vec::new();
    first
        .feed(
            &crate::encode(&hello()).expect("encodes"),
            &kernel,
            &mut out,
        )
        .expect("no error");
    assert!(first.handshook());

    let mut second = Server::new();
    let mut out = Vec::new();
    second
        .feed(
            &crate::encode(&Request::Status).expect("encodes"),
            &kernel,
            &mut out,
        )
        .expect("no error");
    assert!(!second.handshook());

    let mut decoder = Decoder::new();
    decoder.push(&out);
    let response: Response = decoder.next_message().expect("no error").expect("one");
    assert_eq!(response.error_code(), Some("invalid_argument"));
}
