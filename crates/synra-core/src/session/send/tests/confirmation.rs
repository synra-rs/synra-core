use super::*;

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
