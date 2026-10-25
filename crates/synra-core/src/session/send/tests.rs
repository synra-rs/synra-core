//! Failure, cancellation and backpressure tests of the complete shared sender.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use synra_protocol::ids::{DeviceId, TraceId};
use synra_protocol::session::{
    ProgressBitmap, TransferAbortReason, TransferComplete, TransferProgress,
};

use crate::link::{Inbound, PeerLink, memory::MemoryStream};
use crate::peer::Flags;
use crate::session::wire::{Message, envelope_for};
use crate::session::{Received, Receiving, SessionError, SessionEvent};
use crate::transfer::TransferSender;

use super::{SendOptions, WINDOW_BLOCKS, report_progress, send_prepared};

fn links() -> (PeerLink, PeerLink) {
    let (near, far) = MemoryStream::pair_with_capacity(4096);
    let local = DeviceId::new();
    let peer = DeviceId::new();
    let agreed = synra_protocol::handshake::Agreed {
        common: vec![],
        missing_required: vec![],
    };
    (
        PeerLink::new(near, local, peer, agreed.clone(), Flags::production()),
        PeerLink::new(far, peer, local, agreed, Flags::production()),
    )
}

fn options() -> SendOptions {
    SendOptions::new(TraceId::new(), 123, Instant::now() + Duration::from_secs(3))
}

fn sender(root: &tempfile::TempDir, size: usize) -> TransferSender {
    let path = root.path().join("source.bin");
    std::fs::write(&path, vec![9; size]).unwrap();
    TransferSender::open(&path, 1024).unwrap()
}

/// A deliberately uncooperative receiver: acknowledge blocks but let the test control confirmation.
fn receive_body(peer: &mut PeerLink) -> synra_protocol::envelope::Envelope {
    let proposal = peer.receive().unwrap();
    let request: synra_protocol::session::TransferRequest =
        serde_json::from_str(proposal.payload.unwrap().get()).unwrap();
    let total = crate::transfer::plan_blocks(request.byte_length, request.chunk_size)
        .unwrap()
        .len();
    let total = u32::try_from(total).unwrap();
    let mut bitmap = ProgressBitmap::empty(total);
    loop {
        match peer.receive_inbound().unwrap() {
            Inbound::Block { chunk_id, .. } => {
                bitmap.set(chunk_id);
                let progress = TransferProgress {
                    transfer_id: request.transfer_id,
                    received: bitmap.as_bytes().to_vec(),
                    total_blocks: total,
                    bytes_received: request.byte_length,
                };
                let reply = envelope_for(
                    Message::Progress,
                    peer.local(),
                    peer.peer(),
                    proposal.trace_id,
                    123,
                    &progress,
                )
                .unwrap();
                peer.send(&reply).unwrap();
            }
            Inbound::Envelope(envelope) => {
                assert_eq!(envelope.event.as_str(), Message::Complete.name());
                return *envelope;
            }
        }
    }
}

#[test]
fn backpressure_and_a_dropped_block_do_not_break_the_bounded_window() {
    let root = tempfile::tempdir().unwrap();
    let mut sender = sender(&root, 100 * 1024);
    let (mut local, mut peer) = links();
    let options = options();
    let mut progress = Vec::new();
    let destination = root.path().join("received.bin");
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let proposal = peer.receive().unwrap();
            let mut receiver =
                Receiving::accept(&proposal, &destination, proposal.trace_id).unwrap();
            // Intentionally omit one frame after decoding it, then drive the real receiving flow.
            assert!(matches!(
                peer.receive_inbound().unwrap(),
                Inbound::Block { chunk_id: 0, .. }
            ));
            loop {
                match receiver.absorb(&mut peer, 123, options.deadline).unwrap() {
                    Received::Block { .. } => {
                        report_progress(&mut peer, receiver.receiver(), options.trace_id, 123)
                            .unwrap();
                    }
                    Received::Verified { .. } => break,
                    other => panic!("unexpected receiver state: {other:?}"),
                }
            }
        });
        let events = send_prepared(
            &mut local,
            &mut sender,
            options,
            || false,
            |done, _| progress.push(done),
        )
        .unwrap();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, SessionEvent::Verified { .. }))
        );
        let repaired: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                SessionEvent::Resend { missing, .. } => Some(missing.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(repaired, vec![0]);
        worker.join().unwrap();
    });
    assert_eq!(progress.last(), Some(&100));
    assert!(progress.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(std::fs::read(destination).unwrap(), vec![9; 100 * 1024]);
}

#[test]
fn a_peer_cannot_open_the_window_by_acknowledging_unsent_blocks() {
    let root = tempfile::tempdir().unwrap();
    let mut sender = sender(&root, (WINDOW_BLOCKS + 1) * 1024);
    let id = sender.transfer_id();
    let (mut local, mut peer) = links();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            peer.receive().unwrap();
            for _ in 0..WINDOW_BLOCKS {
                peer.receive_inbound().unwrap();
            }
            peer.set_read_timeout(Some(Duration::from_millis(20)));
            assert!(
                matches!(peer.receive_inbound(), Err(crate::LinkError::TimedOut)),
                "the sender must wait instead of opening another window"
            );
            let total = u32::try_from(WINDOW_BLOCKS + 1).unwrap();
            let progress = TransferProgress {
                transfer_id: id,
                received: ProgressBitmap::full(total).as_bytes().to_vec(),
                total_blocks: total,
                bytes_received: u64::from(total) * 1024,
            };
            let reply = envelope_for(
                Message::Progress,
                peer.local(),
                peer.peer(),
                TraceId::new(),
                0,
                &progress,
            )
            .unwrap();
            peer.send(&reply).unwrap();
        });
        assert!(matches!(
            send_prepared(&mut local, &mut sender, options(), || false, |_, _| {}),
            Err(SessionError::BadProgress(_))
        ));
        worker.join().unwrap();
    });
}

#[test]
fn a_wrong_digest_or_transfer_id_cannot_confirm_success() {
    for wrong_id in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut sender = sender(&root, 0);
        let id = sender.transfer_id();
        let digest = sender.digest().as_sri().clone();
        let (mut local, mut peer) = links();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                receive_body(&mut peer);
                let confirmation = TransferComplete {
                    transfer_id: if wrong_id {
                        synra_protocol::ids::TransferId::new()
                    } else {
                        id
                    },
                    digest: if wrong_id {
                        digest
                    } else {
                        crate::transfer::ObjectDigest::of(b"another object")
                            .as_sri()
                            .clone()
                    },
                };
                let reply = envelope_for(
                    Message::Complete,
                    peer.local(),
                    peer.peer(),
                    TraceId::new(),
                    0,
                    &confirmation,
                )
                .unwrap();
                peer.send(&reply).unwrap();
            });
            let error =
                send_prepared(&mut local, &mut sender, options(), || false, |_, _| {}).unwrap_err();
            assert!(if wrong_id {
                matches!(error, SessionError::WrongTransfer { .. })
            } else {
                matches!(
                    error,
                    SessionError::Transfer(crate::TransferError::CompletionMismatch { .. })
                )
            });
            worker.join().unwrap();
        });
    }
}

#[test]
fn cancellation_during_confirmation_sends_one_terminal_abort() {
    let root = tempfile::tempdir().unwrap();
    let mut sender = sender(&root, 0);
    let (mut local, mut peer) = links();
    let cancelled = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let token = Arc::clone(&cancelled);
        let worker = scope.spawn(move || {
            let completion = receive_body(&mut peer);
            token.store(true, Ordering::SeqCst);
            let abort = peer.receive().unwrap();
            let payload: synra_protocol::session::TransferAbort =
                serde_json::from_str(abort.payload.unwrap().get()).unwrap();
            assert_eq!(payload.reason, TransferAbortReason::UserCancelled);
            assert_eq!(abort.trace_id, completion.trace_id);
        });
        let error = send_prepared(
            &mut local,
            &mut sender,
            options(),
            || cancelled.load(Ordering::SeqCst),
            |_, _| {},
        )
        .unwrap_err();
        assert_eq!(error, SessionError::Cancelled);
        worker.join().unwrap();
    });
}

#[test]
fn missing_confirmation_expires_and_restores_caller_timeouts() {
    let root = tempfile::tempdir().unwrap();
    let mut sender = sender(&root, 0);
    let (mut local, mut peer) = links();
    local.set_read_timeout(Some(Duration::from_millis(73)));
    local.set_write_timeout(Some(Duration::from_millis(91)));
    let original = local.timeout_overrides();
    let started = Instant::now();
    let mut options = options();
    options.idle_timeout = Duration::from_millis(150);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            receive_body(&mut peer);
            let notice = peer.receive().unwrap();
            let abort: synra_protocol::session::TransferAbort =
                serde_json::from_str(notice.payload.unwrap().get()).unwrap();
            assert_eq!(abort.reason, TransferAbortReason::IdleTimeout);
        });
        assert_eq!(
            send_prepared(&mut local, &mut sender, options, || false, |_, _| {}),
            Err(SessionError::TimedOut)
        );
        worker.join().unwrap();
    });
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(local.timeout_overrides(), original);
}

#[test]
fn an_expired_total_deadline_never_proposes_or_writes_a_block() {
    let root = tempfile::tempdir().unwrap();
    let mut sender = sender(&root, 1024);
    let (mut local, mut peer) = links();
    let mut options = options();
    options.deadline = Instant::now();
    assert_eq!(
        send_prepared(&mut local, &mut sender, options, || false, |_, _| {}),
        Err(SessionError::TimedOut)
    );
    let notice = peer.receive().unwrap();
    assert_eq!(notice.event.as_str(), Message::Abort.name());
    let payload: synra_protocol::session::TransferAbort =
        serde_json::from_str(notice.payload.unwrap().get()).unwrap();
    assert_eq!(payload.reason, TransferAbortReason::TotalTimeout);
    assert!(!sender.has_sent(0));
}

#[test]
fn duplicate_progress_does_not_keep_an_idle_transfer_alive() {
    let root = tempfile::tempdir().unwrap();
    let mut sender = sender(&root, 1024);
    let id = sender.transfer_id();
    let (mut local, mut peer) = links();
    let mut options = options();
    options.idle_timeout = Duration::from_millis(100);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            peer.receive().unwrap();
            peer.receive_inbound().unwrap();
            let progress = TransferProgress {
                transfer_id: id,
                received: vec![0],
                total_blocks: 1,
                bytes_received: 0,
            };
            let reply = envelope_for(
                Message::Progress,
                peer.local(),
                peer.peer(),
                options.trace_id,
                123,
                &progress,
            )
            .unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(5)));
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                peer.send(&reply).unwrap();
                match peer.receive() {
                    Ok(notice) => {
                        assert_eq!(notice.event.as_str(), Message::Abort.name());
                        break;
                    }
                    Err(crate::LinkError::TimedOut) => {}
                    other => panic!("unexpected reply {other:?}"),
                }
                assert!(Instant::now() < deadline);
            }
        });
        assert_eq!(
            send_prepared(&mut local, &mut sender, options, || false, |_, _| {}),
            Err(SessionError::TimedOut)
        );
        worker.join().unwrap();
    });
}
