use synra_protocol::ids::TraceId;
use synra_protocol::session::{ProgressBitmap, TransferProgress};

use crate::link::Inbound;
use crate::test_support::{file, temp_dir};
use crate::transfer::{TransferReceiver, TransferSender};

use super::super::send::report_progress;
use super::super::wire::{Message, classify, payload_of};
use super::connected;

#[test]
fn a_progress_report_tells_the_sender_which_blocks_to_send_again() {
    // ★ The reason the sender reads between windows. A block that never arrived is reported in a bitmap, and the
    // sender re-sends exactly that one — not the whole file, and not nothing.
    let dir = temp_dir("resend");
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
