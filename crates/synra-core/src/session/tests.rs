//! The transfer's integration tests: both sides of a real link, at once.
//!
//! # Why these are one module rather than one per side
//!
//! Because a transfer *is* the two sides agreeing. A test that drove only a sender would have to invent a receiver's
//! answers, and inventing them is exactly how the daemon's missing progress report stayed invisible: the tests answered the
//! sender, the daemon did not, and every test passed while every real transfer took six seconds.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::ids::{DeviceId, TraceId, TransferId};
use synra_protocol::session::{
    ProgressBitmap, TransferAbort, TransferAbortReason, TransferComplete, TransferProgress,
};

use crate::link::{Inbound, PeerLink};
use crate::peer::Flags;
use crate::transfer::{TransferReceiver, TransferSender};

use super::receive::Receiving;
use super::send::{abort, complete, propose, report_progress, send_file};
use super::receive::Received;
use super::types::{SessionError, SessionEvent};
use super::wire::{Message, classify, envelope_for, payload_of};

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    /// A temporary directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "synra-session-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temp directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut handle = std::fs::File::create(&path).expect("creates");
        handle.write_all(bytes).expect("writes");
        handle.flush().expect("flushes");
        path
    }

    /// Two connected links, as a session would have.
    fn connected() -> (PeerLink, PeerLink) {
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
            PeerLink::new(dialer, device(A), device(B), agreed.clone(), Flags::no_timeout()),
            PeerLink::new(accepted, device(B), device(A), agreed, Flags::no_timeout()),
        )
    }

    fn later() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(10)
    }

    /// An envelope carrying a throwaway payload of the right event.
    fn envelope_of(message: Message) -> Envelope {
        envelope_for(message, device(A), device(B), TraceId::new(), 0, &serde_json::json!({}))
            .expect("builds")
    }

    // ── Names and classification ──────────────────────────────────────────────────────────────────

    #[test]
    fn every_message_name_is_one_the_protocol_declares() {
        // ★ The names are the protocol's, and a transfer that used a name outside its set would be a message the far end
        // refuses as an unknown event.
        for message in [
            Message::Request,
            Message::Chunk,
            Message::Complete,
            Message::Abort,
            Message::Progress,
        ] {
            assert!(
                EventName::parse(message.name()).is_ok(),
                "{} is not a name this build accepts",
                message.name()
            );
            assert!(
                synra_protocol::event::DataPlaneEvent::from_str_opt(message.name()).is_some(),
                "{} is not a data-plane event",
                message.name()
            );
        }
    }

    #[test]
    fn a_classified_message_is_recognised_and_a_stranger_is_not() {
        // ★ A link carries every kind of message, so a dispatcher that claimed an unrelated event would break whichever
        // feature owned it.
        assert_eq!(classify(&envelope_of(Message::Request)), Some(Message::Request));
        assert_eq!(classify(&envelope_of(Message::Progress)), Some(Message::Progress));

        let stranger = Envelope::outbound(
            OutboundSpec {
                event: EventName::parse("device.ping").expect("a name"),
                target: device(B),
                from: device(A),
                trace_id: TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&serde_json::Value>,
        )
        .expect("builds");
        assert_eq!(classify(&stranger), None, "an unrelated event was claimed");
    }

    // ── A whole transfer, with no socket ──────────────────────────────────────────────────────────

    #[test]
    fn a_file_moves_from_one_side_to_the_other() {
        // ★ The whole point of this module: propose, move every block, confirm. The pieces have their own tests; what none
        // of those can see is the *sequence*, and this is the sequence a real transfer takes.
        let dir = TempDir::new("whole");
        let content: Vec<u8> = (0..=255u8).cycle().take(20_000).collect();
        let source = file(&dir, "source.bin", &content);
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let transfer = TransferSender::open(&source, 1_024).expect("opens");
        let trace = TraceId::new();

        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");
        assert_eq!(receiving.transfer_id(), transfer.transfer_id());

        // Every block, straight through — the reliable-link case.
        for block in transfer.blocks() {
            let data = transfer.read_block(block.index).expect("reads");
            side_a.send_chunk(block.index, &data).expect("sends");
            match receiving.absorb(&mut side_b, 0, later()).expect("absorbs") {
                Received::Block { index, duplicate } => {
                    assert_eq!(index, block.index);
                    assert!(!duplicate);
                }
                other => panic!("expected a stored block, got {other:?}"),
            }
        }

        complete(&mut side_a, &transfer, trace, 0).expect("completes");
        match receiving.absorb(&mut side_b, 0, later()).expect("absorbs") {
            Received::Verified { transfer_id, digest } => {
                assert_eq!(transfer_id, transfer.transfer_id());
                assert_eq!(digest, transfer.digest().encoded());
            }
            other => panic!("expected a verification, got {other:?}"),
        }
        assert_eq!(std::fs::read(&destination).expect("reads back"), content);
    }

    #[test]
    fn the_receiver_confirms_back_and_the_sender_hears_it() {
        // ★ The confirmation is what tells a sender the file arrived, and it travels as a completion — the same message
        // kind, in the other direction.
        let dir = TempDir::new("confirm");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let transfer = TransferSender::open(&source, 4).expect("opens");
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        for block in transfer.blocks() {
            let data = transfer.read_block(block.index).expect("reads");
            side_a.send_chunk(block.index, &data).expect("sends");
            receiving.absorb(&mut side_b, 0, later()).expect("absorbs");
        }
        complete(&mut side_a, &transfer, trace, 0).expect("completes");
        receiving.absorb(&mut side_b, 0, later()).expect("verifies");

        // The sender reads the confirmation.
        let Inbound::Envelope(envelope) = side_a.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        assert_eq!(classify(&envelope), Some(Message::Complete));
        let confirmation: TransferComplete = payload_of(&envelope, "complete").expect("reads");
        assert_eq!(confirmation.transfer_id, transfer.transfer_id());
        assert_eq!(confirmation.digest.encoded(), transfer.digest().encoded());
    }

    // ── A dropped block, and the report that rescues it ───────────────────────────────────────────

    #[test]
    fn a_progress_report_tells_the_sender_which_blocks_to_send_again() {
        // ★ The reason the sender reads between windows. A block that never arrived is reported in a bitmap, and the
        // sender re-sends exactly that one — not the whole file, and not nothing.
        let dir = TempDir::new("resend");
        let content: Vec<u8> = (0..=255u8).cycle().take(4_000).collect();
        let source = file(&dir, "source.bin", &content);
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let transfer = TransferSender::open(&source, 512).expect("opens");
        let trace = TraceId::new();
        let request = transfer.request();
        let mut receiving = TransferReceiver::accept(&request, &destination).expect("accepts");

        // Everything except block 1, which "was lost".
        for block in transfer.blocks() {
            if block.index == 1 {
                continue;
            }
            let data = transfer.read_block(block.index).expect("reads");
            side_a.send_chunk(block.index, &data).expect("sends");
            let Inbound::Block { chunk_id, data } = side_b.receive_inbound().expect("receives")
            else {
                panic!("expected a block");
            };
            receiving.absorb(chunk_id, &data).expect("absorbs");
        }

        report_progress(&mut side_b, &receiving, trace, 0).expect("reports");
        let Inbound::Envelope(envelope) = side_a.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        assert_eq!(classify(&envelope), Some(Message::Progress));
        let progress: TransferProgress = payload_of(&envelope, "progress").expect("reads");
        assert_eq!(progress.transfer_id, transfer.transfer_id());
        let bitmap = ProgressBitmap::from_bytes(progress.received, progress.total_blocks)
            .expect("a matching bitmap");
        assert_eq!(bitmap.missing(), vec![1]);

        // And that one block completes the transfer.
        let data = transfer.read_block(1).expect("reads");
        side_a.send_chunk(1, &data).expect("sends");
        let Inbound::Block { chunk_id, data } = side_b.receive_inbound().expect("receives") else {
            panic!("expected a block");
        };
        receiving.absorb(chunk_id, &data).expect("absorbs");
        receiving.finish(&request.digest).expect("verifies");
        assert_eq!(std::fs::read(&destination).expect("reads back"), content);
    }

    #[test]
    fn a_progress_bitmap_that_disagrees_with_the_size_is_refused() {
        // A bitmap of the wrong length means the two sides differ about the transfer's size, which is a disagreement no
        // amount of re-sending fixes.
        assert!(ProgressBitmap::from_bytes(vec![0, 0], 2).is_err());
        assert!(ProgressBitmap::from_bytes(vec![0], 2).is_ok());
    }



    // ── The whole round trip, both ends at once ───────────────────────────────────────────────────

    #[test]
    fn a_receiver_waits_out_a_quiet_link_rather_than_abandoning_the_transfer() {
        // ★ The read a receiver spends most of a transfer sitting on, and the bug that made the completion arrive about half
        // the time: this used to propagate the socket's timeout with `?`, so the caller saw a link failure and closed the
        // connection while the sender's completion was one frame behind the last block. The deadline is what bounds the
        // wait — not the socket — so a message that is merely late is still read.
        let dir = TempDir::new("quiet-link");
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
        let dir = TempDir::new("round-trip");
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

    // ── Receiving ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_receiver_accepts_a_proposal_and_reports_where_it_is_writing() {
        let dir = TempDir::new("accept");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");
        let destination = dir.path().join("copy.bin");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");

        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");
        assert_eq!(receiving.transfer_id(), transfer.transfer_id());
        assert_eq!(receiving.path(), destination);
        assert_eq!(receiving.missing().len(), 2);
    }

    #[test]
    fn a_message_from_another_feature_is_not_swallowed_by_the_transfer() {
        // ★ A transfer must not eat every message on the link, or it would break whatever else is using the connection.
        let dir = TempDir::new("ignored");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        let unrelated = Envelope::outbound(
            OutboundSpec {
                event: EventName::parse("device.ping").expect("a name"),
                target: device(B),
                from: device(A),
                trace_id: trace,
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&serde_json::Value>,
        )
        .expect("builds");
        side_a.send(&unrelated).expect("sends");

        assert_eq!(
            receiving.absorb(&mut side_b, 0, later()).expect("absorbs"),
            Received::Ignored
        );
    }

    #[test]
    fn an_abort_from_the_peer_ends_the_transfer_with_its_reason() {
        let dir = TempDir::new("abort");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        abort(&mut side_a, transfer.transfer_id(), TransferAbortReason::UserCancelled, trace, 0)
            .expect("aborts");
        assert_eq!(
            receiving.absorb(&mut side_b, 0, later()).expect("absorbs"),
            Received::Aborted {
                transfer_id: transfer.transfer_id(),
                reason: TransferAbortReason::UserCancelled,
            }
        );
    }

    #[test]
    fn a_completion_for_another_transfer_is_refused() {
        // ★ Two files at once would otherwise be finalised against each other's digests.
        let dir = TempDir::new("wrong-completion");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        let stray = TransferComplete {
            transfer_id: TransferId::new(),
            digest: transfer.digest().as_sri().clone(),
        };
        let envelope =
            envelope_for(Message::Complete, device(A), device(B), trace, 0, &stray).expect("builds");
        side_a.send(&envelope).expect("sends");

        match receiving.absorb(&mut side_b, 0, later()) {
            Err(SessionError::WrongTransfer { .. }) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_completion_that_does_not_verify_is_reported_and_the_peer_is_told_why() {
        // ★ A digest mismatch and a missing block need different answers from the sender, so the transfer reports which it
        // was — and the peer hears about it rather than being left waiting for a confirmation that will not come.
        let dir = TempDir::new("no-verify");
        let destination = dir.path().join("copy.bin");
        let source = file(&dir, "source.bin", b"abcdefgh");
        let transfer = TransferSender::open(&source, 4).expect("opens");

        let (mut side_a, mut side_b) = connected();
        let trace = TraceId::new();
        propose(&mut side_a, &transfer, trace, 0).expect("proposes");
        let Inbound::Envelope(envelope) = side_b.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        let mut receiving = Receiving::accept(&envelope, &destination, trace).expect("accepts");

        // The completion arrives with no blocks sent at all.
        complete(&mut side_a, &transfer, trace, 0).expect("completes");
        match receiving.absorb(&mut side_b, 0, later()).expect("absorbs") {
            Received::Failed { transfer_id, why } => {
                assert_eq!(transfer_id, transfer.transfer_id());
                assert!(!why.is_empty());
            }
            other => panic!("expected a failure, got {other:?}"),
        }

        // And the sender is told, with a reason.
        let Inbound::Envelope(envelope) = side_a.receive_inbound().expect("receives") else {
            panic!("expected an envelope");
        };
        assert_eq!(classify(&envelope), Some(Message::Abort));
        let notice: TransferAbort = payload_of(&envelope, "abort").expect("reads");
        assert_eq!(notice.reason, TransferAbortReason::IoError);
    }

    // ── The one-shot ──────────────────────────────────────────────────────────────────────────────
