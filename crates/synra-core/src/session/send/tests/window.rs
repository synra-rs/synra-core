use super::*;

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
