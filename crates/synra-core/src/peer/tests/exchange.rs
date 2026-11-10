use std::net::TcpStream;
use synra_protocol::frame::{Frame, FrameDecoder, FrameKind};
use synra_protocol::handshake::{Hello, HelloAck, PROTOCOL_VERSION, SessionNonce};
use synra_protocol::session::PlatformKind;
use super::super::{Flags, HandshakeError, accept, dial};
use super::super::wire::{hello_ack_frame, hello_frame, json_payload, read_frame, write_frame};
use super::{ACCEPTOR, DIALER, device, listener, peer};

#[test]
fn a_dialer_and_an_acceptor_complete_a_handshake() {
    // ★ The end-to-end test, on a real loopback socket. The types here are the ones that cross the wire, so a test
    // that stubbed the transport would be a test of the stub — and the bug this layer can have is a mismatch between
    // what one side writes and what the other reads.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout())
    });

    let (stream, negotiated) =
        dial(address, &theirs, 1, Flags::no_timeout()).expect("completes");
    drop(stream);
    let (_, accepted) = serving.join().expect("the thread finished").expect("accepts");

    // Each side learned the other.
    assert_eq!(negotiated.device_id, device(ACCEPTOR));
    assert_eq!(negotiated.display_name, "Laptop");
    assert_eq!(negotiated.platform, PlatformKind::Desktop);
    assert_eq!(accepted.device_id, device(DIALER));
    assert_eq!(accepted.display_name, "Phone");
    assert_eq!(accepted.platform, PlatformKind::Android);
}

#[test]
fn both_ends_agree_on_the_same_features() {
    // ★ The computation is the same on both sides, and a dialer and an acceptor that disagreed would each believe a
    // different set is available — with the failure landing at the first transfer that used one of them.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout())
    });
    let (stream, mine) = dial(address, &theirs, 1, Flags::no_timeout()).expect("completes");
    drop(stream);
    let (_, theirs_side) = serving.join().expect("finished").expect("accepts");

    assert_eq!(mine.agreed, theirs_side.agreed);
    assert!(mine.is_usable());
    assert!(!mine.agreed.common.is_empty(), "no features in common");
}



#[test]
fn a_peer_that_hangs_up_before_saying_hello_is_reported_as_closed() {
    // ★ The ordinary shape of a port scan and of a user who closed a laptop. A caller that could not tell it from a
    // decode error would log a fault for every scan.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout())
    });

    // A connection that sends nothing and closes.
    let probe = TcpStream::connect(address).expect("connects");
    drop(probe);

    match serving.join().expect("finished") {
        Err(HandshakeError::Closed) => {}
        other => panic!("expected a closed connection, got {other:?}"),
    }
}

#[test]
fn a_dialer_that_reaches_a_socket_that_says_nothing_reports_closed_rather_than_waiting() {
    // The other direction: a listener that accepts and does nothing. With a timeout the dialer gives up; the
    // assertion here uses the closed path, because `TcpStream` on a loopback cannot be made to time out reliably.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accepts");
        // Say nothing, then close.
        drop(stream);
    });

    match dial(address, &theirs, 1, Flags::no_timeout()) {
        Err(HandshakeError::Closed) => {}
        other => panic!("expected a closed connection, got {other:?}"),
    }
    serving.join().expect("finished");
}

#[test]
fn a_hello_that_is_not_a_hello_is_refused() {
    // A peer that opens with the wrong frame is one this exchange cannot continue with, and the message names what
    // was expected.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout())
    });

    let mut stream = TcpStream::connect(address).expect("connects");
    write_frame(&mut stream, &Frame::empty(FrameKind::Ping)).expect("writes");

    match serving.join().expect("finished") {
        Err(HandshakeError::Unexpected { expected, .. }) => assert_eq!(expected, "Hello"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_hello_carrying_an_unreasonable_endpoint_list_is_refused() {
    // ★ The announcement is attacker-controlled input, and an unbounded endpoint list would be an unbounded amount
    // of dialling on this device's behalf. The validation is what bounds it.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);

    let serving = std::thread::spawn(move || {
        accept(&listener, &ours, 1, Flags::no_timeout())
    });

    let mut stream = TcpStream::connect(address).expect("connects");
    let mut hello = peer(DIALER, "Phone", PlatformKind::Android).hello(SessionNonce::random(), 1);
    hello.endpoints = (0..Hello::MAX_ENDPOINTS + 4).map(|i| format!("10.0.0.{i}:47100")).collect();
    write_frame(&mut stream, &hello_frame(&hello).expect("encodes"))
        .expect("writes");

    match serving.join().expect("finished") {
        Err(HandshakeError::Invalid { why }) => assert!(!why.is_empty()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_refusal_from_the_acceptor_reaches_the_dialer() {
    // A refusal is a complete answer, and the dialer reports it rather than building a session on a declined link.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut decoder = FrameDecoder::new();
        let _ = read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello");
        // A refusal, which the protocol says is a complete answer in itself.
        let ack = HelloAck::refuse(
            device(ACCEPTOR),
            "Laptop",
            PlatformKind::Desktop,
            "0.1.0-test",
            SessionNonce::random(),
            synra_protocol::handshake::RefusalReason::Malformed,
        );
        write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
            .expect("writes");
    });

    match dial(address, &theirs, 1, Flags::no_timeout()) {
        Err(HandshakeError::Refused { reason }) => assert!(!reason.is_empty()),
        other => panic!("expected a refusal, got {other:?}"),
    }
    serving.join().expect("finished");
}

#[test]
fn an_ack_echoing_a_different_nonce_is_refused() {
    // ★ The nonce ties an answer to the attempt that asked for it. An answer carrying a different one is a recorded
    // or mis-routed message, and continuing would build a session on a reply to somebody else's question.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut decoder = FrameDecoder::new();
        let _ = read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello");
        // A fresh nonce rather than the one that arrived.
        let ack = ours.hello_ack(SessionNonce::random(), 1);
        write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
            .expect("writes");
    });

    match dial(address, &theirs, 1, Flags::no_timeout()) {
        Err(HandshakeError::NonceMismatch) => {}
        other => panic!("expected a nonce mismatch, got {other:?}"),
    }
    serving.join().expect("finished");
}

#[test]
fn an_ack_naming_a_different_protocol_is_refused() {
    // A peer speaking another version is refused here rather than failing on the third message with a decode error
    // about a field neither end can name.
    let listener = listener();
    let address = listener.local_addr().expect("an address");
    let ours = peer(ACCEPTOR, "Laptop", PlatformKind::Desktop);
    let theirs = peer(DIALER, "Phone", PlatformKind::Android);

    let serving = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut decoder = FrameDecoder::new();
        let hello: Hello =
            json_payload(&read_frame(&mut stream, &mut decoder, Flags::no_timeout()).expect("a hello"), "Hello")
                .expect("reads");
        let mut ack = ours.hello_ack(hello.nonce, 1);
        ack.protocol = PROTOCOL_VERSION + 1;
        write_frame(&mut stream, &hello_ack_frame(&ack).expect("encodes"))
            .expect("writes");
    });

    match dial(address, &theirs, 1, Flags::no_timeout()) {
        Err(HandshakeError::VersionMismatch { theirs, ours }) => {
            assert_eq!(theirs, PROTOCOL_VERSION + 1);
            assert_eq!(ours, PROTOCOL_VERSION);
        }
        other => panic!("expected a version mismatch, got {other:?}"),
    }
    serving.join().expect("finished");
}
