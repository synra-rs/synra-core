use super::*;

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
