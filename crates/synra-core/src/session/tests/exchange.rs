use synra_protocol::ids::TraceId;
use synra_protocol::session::TransferComplete;

use crate::link::Inbound;
use crate::test_support::{file, temp_dir};
use crate::transfer::TransferSender;

use super::super::receive::{Received, Receiving};
use super::super::send::{complete, propose};
use super::super::wire::{Message, classify, payload_of};
use super::{connected, later};

#[test]
fn a_file_moves_from_one_side_to_the_other() {
    // ★ The whole point of this module: propose, move every block, confirm. The pieces have their own tests; what none
    // of those can see is the *sequence*, and this is the sequence a real transfer takes.
    let dir = temp_dir("whole");
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
    let dir = temp_dir("confirm");
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
