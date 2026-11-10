use synra_protocol::ids::TransferId;

use crate::test_support::{file, temp_dir};

use super::super::{Absorbed, ObjectDigest, TransferError, TransferReceiver, TransferSender};

#[test]
fn a_whole_transfer_arrives_intact() {
    // ★ The end-to-end case, with no socket: a sender's blocks go into a receiver and the file that lands on disk has
    // the bytes the original had, checked by the digest rather than by comparing lengths.
    let dir = temp_dir("round-trip");
    let content: Vec<u8> = (0..=255u8).cycle().take(5_000).collect();
    let source = file(&dir, "source.bin", &content);

    let sender = TransferSender::open(&source, 512).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    for block in sender.blocks() {
        let data = sender.read_block(block.index).expect("reads");
        assert_eq!(receiver.absorb(block.index, &data).expect("absorbs"), Absorbed::Stored);
    }

    let digest = receiver.finish(sender.digest().as_sri()).expect("finishes");
    assert!(digest.matches(sender.digest().as_sri()));
    assert_eq!(std::fs::read(&destination).expect("reads back"), content);
}

#[test]
fn a_duplicate_block_is_accepted_and_changes_nothing() {
    // ★ A re-sent block is what a resumption *is*. Refusing it would make a retry after a dropped acknowledgement look
    // like corruption, and the sender could not tell the two apart.
    let dir = temp_dir("duplicate");
    let source = file(&dir, "source.bin", b"abcdefgh");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    let first = sender.read_block(0).expect("reads");
    assert_eq!(receiver.absorb(0, &first).expect("absorbs"), Absorbed::Stored);
    assert_eq!(receiver.absorb(0, &first).expect("absorbs"), Absorbed::Duplicate);
    assert_eq!(receiver.received_count(), 1, "a duplicate did not count twice");
    assert_eq!(receiver.bytes_received(), 4);
}

#[test]
fn a_duplicate_with_different_bytes_does_not_overwrite_the_first() {
    // ★ The subtle case. A block that arrives twice with *different* content is either a retry whose first copy was
    // corrupt or an attack; either way the first copy stands and the digest decides at the end. Applying the second
    // would let anyone who can inject a packet rewrite a file that had already arrived correctly.
    //
    // Both blocks are filled, because `finish` refuses an incomplete transfer before it hashes anything — the first
    // version of this absorbed one block and then asserted a successful finish, which was the test being wrong rather
    // than the code.
    let dir = temp_dir("duplicate-different");
    let source = file(&dir, "source.bin", b"aaaabbbb");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    receiver.absorb(0, b"aaaa").expect("absorbs");
    receiver.absorb(1, b"bbbb").expect("absorbs");
    // The second copy of block 0 disagrees with the first, and the first is what stays.
    assert_eq!(receiver.absorb(0, b"zzzz").expect("absorbs"), Absorbed::Duplicate);
    receiver.finish(sender.digest().as_sri()).expect("the first copy was right");
    assert_eq!(std::fs::read(&destination).expect("reads"), b"aaaabbbb");
}

#[test]
fn blocks_that_arrive_out_of_order_are_written_where_they_belong() {
    // A network does not promise order across a resumption, so a receiver that appended would produce a file of the
    // right length with the wrong bytes — and only the digest would catch it.
    let dir = temp_dir("out-of-order");
    let content: Vec<u8> = (0..=255u8).cycle().take(1_000).collect();
    let source = file(&dir, "source.bin", &content);
    let sender = TransferSender::open(&source, 256).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    // Backwards.
    for block in sender.blocks().iter().rev() {
        let data = sender.read_block(block.index).expect("reads");
        receiver.absorb(block.index, &data).expect("absorbs");
    }
    receiver.finish(sender.digest().as_sri()).expect("finishes");
    assert_eq!(std::fs::read(&destination).expect("reads back"), content);
}

#[test]
fn a_receiver_can_be_asked_whether_a_frame_belongs_to_it() {
    // ★ `transfer_id` is in the request and in every frame so a block naming an unknown transfer can be refused rather
    // than applied to whatever is in progress. Without it, two files sent at once interleave into one corrupt one.
    //
    // The check is the **caller's**, because the id is in the frame and this layer never sees a frame — so what this
    // asserts is that the receiver exposes the id it was proposed with, which is what the caller compares against.
    let dir = temp_dir("unknown-block");
    let source = file(&dir, "source.bin", b"abcdefgh");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    assert_eq!(receiver.transfer_id(), sender.transfer_id());
    // A different transfer's id, which is what a spliced frame carries.
    let other = TransferId::new();
    assert_ne!(other, receiver.transfer_id());
}

#[test]
fn a_block_longer_than_the_agreed_chunk_size_is_refused() {
    // ★ The chunk size is the sender's promise about the layout. A long block means the two disagree about where
    // every later block starts, so accepting it would misplace every subsequent byte.
    let dir = temp_dir("too-long");
    let source = file(&dir, "source.bin", b"abcdefghijklmnop");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    match receiver.absorb(0, b"toolongblock") {
        Err(TransferError::BlockTooLong { len, size }) => {
            assert_eq!(len, 12);
            assert_eq!(size, 4);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_block_past_the_end_of_the_object_is_refused() {
    let dir = temp_dir("past-end");
    let source = file(&dir, "source.bin", b"abcd");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    assert!(matches!(
        receiver.absorb(99, b"abcd"),
        Err(TransferError::BlockOutOfRange { index: 99, .. })
    ));
}

#[test]
fn a_transfer_that_is_missing_blocks_says_how_many() {
    // ★ Reported as "missing" rather than as a digest mismatch: a file with a hole in it is incomplete, and saying so
    // is more useful than saying the bytes were wrong.
    let dir = temp_dir("incomplete");
    let source = file(&dir, "source.bin", b"abcdefghijkl");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    receiver.absorb(0, b"abcd").expect("absorbs");
    match receiver.finish(sender.digest().as_sri()) {
        Err(TransferError::Incomplete { missing, total }) => {
            assert_eq!(missing, 2);
            assert_eq!(total, 3);
        }
        other => panic!("expected an incomplete refusal, got {other:?}"),
    }
}

#[test]
fn a_completion_naming_a_different_digest_is_refused_without_reading_the_file() {
    // ★ The completion and the request are two messages, so a disagreement means something rewrote one of them. The
    // check runs before the bytes are hashed, so a tampered transfer costs no I/O.
    let dir = temp_dir("completion-mismatch");
    let source = file(&dir, "source.bin", b"abcd");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");
    receiver.absorb(0, b"abcd").expect("absorbs");

    let other = ObjectDigest::of(b"something else").as_sri().clone();
    match receiver.finish(&other) {
        Err(TransferError::CompletionMismatch { found, promised }) => {
            assert_eq!(found, other.encoded());
            assert_eq!(promised, sender.digest().encoded());
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn bytes_that_arrive_wrong_are_caught_by_the_digest() {
    // ★ The rule everything follows: the digest is the only proof. Every block arrived, the length is right, and the
    // transfer is still refused — because the bytes are not the ones that were promised.
    let dir = temp_dir("wrong-bytes");
    let source = file(&dir, "source.bin", b"abcdefgh");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    receiver.absorb(0, b"abcd").expect("absorbs");
    // The right length, the wrong content.
    receiver.absorb(1, b"ZZZZ").expect("absorbs");

    match receiver.finish(sender.digest().as_sri()) {
        Err(TransferError::DigestMismatch { actual, expected }) => {
            assert_ne!(actual, expected);
            assert_eq!(expected, sender.digest().encoded());
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
}

#[test]
fn a_zero_chunk_size_proposal_is_refused() {
    let dir = temp_dir("zero-chunk");
    let source = file(&dir, "source.bin", b"abcd");
    let mut request = TransferSender::open(&source, 4).expect("opens").request();
    request.chunk_size = 0;
    match TransferReceiver::accept(&request, &dir.path().join("copy.bin")) {
        Err(TransferError::ZeroChunkSize(0)) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_empty_file_transfers_as_one_empty_block() {
    // The degenerate case, end to end: a plan with no blocks would make a zero-byte file impossible to send.
    let dir = temp_dir("empty-round-trip");
    let source = file(&dir, "empty.bin", b"");
    let sender = TransferSender::open(&source, 256).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    assert_eq!(sender.blocks().len(), 1);
    receiver.absorb(0, b"").expect("absorbs nothing");
    receiver.finish(sender.digest().as_sri()).expect("finishes");
    assert_eq!(std::fs::read(&destination).expect("reads"), b"");
}

#[test]
fn the_receivers_bitmap_is_what_the_progress_message_carries() {
    // The bitmap is the protocol's own type, so the progress message needs no conversion — and what a sender learns
    // from it is exactly what the receiver holds.
    let dir = temp_dir("bitmap");
    let source = file(&dir, "source.bin", b"abcdefghijkl");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("copy.bin");
    let mut receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");

    receiver.absorb(0, b"abcd").expect("absorbs");
    receiver.absorb(2, b"ijkl").expect("absorbs");
    let bitmap = receiver.bitmap();
    assert!(bitmap.contains(0));
    assert!(!bitmap.contains(1));
    assert!(bitmap.contains(2));
    assert_eq!(bitmap.missing(), vec![1]);
    assert_eq!(bitmap.total_blocks(), 3);
}

#[test]
fn a_receivers_debug_form_omits_the_path() {
    let dir = temp_dir("recv-debug");
    let source = file(&dir, "source.bin", b"abcd");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("secret-name.bin");
    let receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");
    let text = format!("{receiver:?}");
    assert!(!text.contains("secret-name"), "{text}");
    assert!(text.contains("total"), "{text}");
}
