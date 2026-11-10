use synra_protocol::ids::TraceId;

use crate::link::{Inbound, PeerLink};
use crate::peer::Flags;
use crate::test_support::{file, temp_dir};
use crate::transfer::TransferSender;

use super::super::receive::{Received, Receiving};
use super::super::send::{propose, report_progress, send_file};
use super::super::types::SessionEvent;
use super::{A, B, device, later};

#[test]
fn a_receiver_waits_out_a_quiet_link_rather_than_abandoning_the_transfer() {
    // ★ The read a receiver spends most of a transfer sitting on, and the bug that made the completion arrive about half
    // the time: this used to propagate the socket's timeout with `?`, so the caller saw a link failure and closed the
    // connection while the sender's completion was one frame behind the last block. The deadline is what bounds the
    // wait — not the socket — so a message that is merely late is still read.
    let dir = temp_dir("quiet-link");
    let source = file(&dir, "source.bin", b"abcdefgh");
    let destination = dir.path().join("copy.bin");
    let transfer = TransferSender::open(&source, 4).expect("opens");

    // Production flags, so the socket has the short real timeout that used to end the transfer.
    let (mut side_a, mut side_b) = connected_with(Flags::production());
    let trace = TraceId::new();
    propose(&mut side_a, &transfer, trace, 0).expect("proposes");
    let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
        panic!("expected a proposal");
    };
    let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

    // Nothing is sent for longer than the link's read timeout, then one block arrives. A receiver that gave up at the
    // timeout would never see it.
    let quiet_for = synra_protocol::limits::HELLO_TIMEOUT + std::time::Duration::from_millis(400);
    let writer = std::thread::spawn(move || {
        std::thread::sleep(quiet_for);
        let data = transfer.read_block(0).expect("reads");
        side_a.send_chunk(0, &data).expect("sends");
        side_a
    });

    // A deadline far beyond the quiet period: the wait is bounded by this, not by the socket.
    let received = receiving
        .absorb(&mut side_b, 0, later())
        .expect("a quiet link is not a failure");
    assert!(
        matches!(received, Received::Block { index: 0, .. }),
        "the receiver gave up on a quiet link: {received:?}"
    );
    let _ = writer.join().expect("the writer finished");
}

/// Two connected links under given flags.
fn connected_with(flags: Flags) -> (PeerLink, PeerLink) {
    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
    let address = listener.local_addr().expect("an address");
    let dialer = std::net::TcpStream::connect(address).expect("connects");
    let (accepted, _) = listener.accept().expect("accepts");
    let agreed = synra_protocol::handshake::Agreed {
        common: Vec::new(),
        missing_required: Vec::new(),
    };
    (
        PeerLink::new(dialer, device(A), device(B), agreed.clone(), flags),
        PeerLink::new(accepted, device(B), device(A), agreed, flags),
    )
}

#[test]
fn a_file_moves_and_the_sender_is_told_it_arrived() {
    // ★ This is the flow a daemon runs, and it is the one that was broken: `send_file` on one thread, a receiver
    // answering on the other, **production flags** so the socket has the real six-second read timeout, and a report
    // after every block exactly as the daemon sends. An earlier version moved the file byte-for-byte and then reported
    // a broken link, and nothing smaller than this test could tell the two apart.
    let dir = temp_dir("round-trip");
    // ★ The daemon's own figures, which is the point: an earlier version of this test used a small chunk size and it
    // passed, while the daemon — which uses `DEFAULT_CHUNK_SIZE` — moved the file and then reported a broken link. A
    // test that does not use the sender's real block size cannot see a block-size problem.
    let content: Vec<u8> = (0..=255u8).cycle().take(600_000).collect();
    let source = file(&dir, "source.bin", &content);
    let destination = dir.path().join("copy.bin");
    let target = destination.clone();

    let (mut side_a, side_b) = connected_with(Flags::production());
    let trace = TraceId::new();

    // The receiver, exactly as the daemon drives it: read the proposal, absorb, report, and answer the completion.
    let reports = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reports_in = std::sync::Arc::clone(&reports);
    let receiver = std::thread::spawn(move || {
        let mut side_b = side_b;
        let proposal = side_b.receive_inbound().expect("receives the proposal");
        let Inbound::Envelope(envelope) = proposal else {
            panic!("expected a proposal");
        };
        let mut receiving = Receiving::accept(&envelope, &target, trace).expect("accepts");
        let generous = || std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            match receiving.absorb(&mut side_b, 0, generous()).expect("absorbs") {
                Received::Block { .. } => {
                    report_progress(&mut side_b, receiving.receiver(), trace, 0)
                        .expect("reports");
                    reports_in.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Received::Verified { digest, .. } => return digest,
                other => panic!("the receiver stopped early: {other:?}"),
            }
        }
    });

    let events = send_file(
        &mut side_a,
        &source,
        crate::transfer::DEFAULT_CHUNK_SIZE,
        trace,
        0,
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    )
    .expect("sends");

    let digest = receiver.join().expect("the receiver finished");
    assert!(
        events.iter().any(|event| matches!(event, SessionEvent::Verified { .. })),
        "the sender was never told the file arrived: {events:?}"
    );
    assert_eq!(std::fs::read(&destination).expect("reads back"), content);
    assert!(!digest.is_empty());
}
