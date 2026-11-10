use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::ids::{TraceId, TransferId};
use synra_protocol::session::{TransferAbort, TransferAbortReason, TransferComplete};

use crate::link::Inbound;
use crate::test_support::{file, temp_dir};
use crate::transfer::TransferSender;

use super::super::receive::{Received, Receiving};
use super::super::send::{abort, complete, propose};
use super::super::types::SessionError;
use super::super::wire::{Message, classify, envelope_for, payload_of};
use super::{A, B, connected, device, later};

#[test]
fn a_receiver_accepts_a_proposal_and_reports_where_it_is_writing() {
    let dir = temp_dir("accept");
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
    let dir = temp_dir("ignored");
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
    let dir = temp_dir("abort");
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
    let dir = temp_dir("wrong-completion");
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
    let dir = temp_dir("no-verify");
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
