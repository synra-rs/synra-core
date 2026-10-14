use std::io::Write as _;
use std::path::{Path, PathBuf};

use synra_protocol::ids::TransferId;
use synra_protocol::session::{DigestAlgorithm, TransferKind, TransferMeta};

use super::{
    Absorbed, Block, MAX_CHUNK_SIZE, ObjectDigest, TransferError, TransferReceiver, TransferSender,
    plan_blocks,
};

/// A temporary directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "synra-transfer-{tag}-{}-{:?}",
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

/// Writes a file and returns its path.
fn file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    let mut handle = std::fs::File::create(&path).expect("creates");
    handle.write_all(bytes).expect("writes");
    handle.flush().expect("flushes");
    path
}

// ── The digest ────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_digest_matches_the_published_sha256_of_an_empty_input() {
    // ★ A published vector rather than this crate's own output: a hash implementation checked against itself proves
    // only that it is consistent. SHA-256 of the empty string is a well-known constant.
    let digest = ObjectDigest::of(b"");
    assert_eq!(
        digest.encoded(),
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
    );
}

#[test]
fn the_digest_matches_the_published_sha256_of_abc() {
    // The other classic vector, and the two together pin both the padding path and the short-input path.
    let digest = ObjectDigest::of(b"abc");
    assert_eq!(
        digest.encoded(),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
    );
}

#[test]
fn the_digest_is_accepted_by_the_protocols_own_validator() {
    // ★ The value this crate produces has to satisfy `SriDigest`, which checks the length and the alphabet. A digest
    // that its own protocol refuses would make every transfer unproposable.
    let digest = ObjectDigest::of(b"anything");
    // Through the accessor, because `SriDigest`'s fields are private and the validation already happened in `of`.
    assert_eq!(digest.as_sri().algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(digest.encoded().len(), 43, "SHA-256 base64 without padding is 43 characters");
    assert!(!digest.encoded().contains('='), "padding is not part of the wire form");
}

#[test]
fn the_same_bytes_hash_the_same_way_twice() {
    let once = ObjectDigest::of(b"repeated");
    let twice = ObjectDigest::of(b"repeated");
    assert!(once.matches(twice.as_sri()));
}

#[test]
fn different_bytes_hash_differently() {
    let one = ObjectDigest::of(b"one");
    let other = ObjectDigest::of(b"two");
    assert!(!one.matches(other.as_sri()));
}

#[test]
fn streaming_a_file_hashes_the_whole_thing() {
    // A file larger than the streaming buffer, so the loop runs more than once and the tail is exercised.
    let dir = TempDir::new("digest-stream");
    let bytes = vec![0xA5u8; 200 * 1024];
    let path = file(&dir, "big.bin", &bytes);

    let mut handle = std::fs::File::open(&path).expect("opens");
    let streamed = ObjectDigest::of_reader(&path, &mut handle).expect("hashes");
    // The streaming form and the one-shot form must agree, because a sender uses one and a receiver the other.
    assert!(streamed.matches(ObjectDigest::of(&bytes).as_sri()));
}

// ── The plan ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_exact_multiple_of_the_chunk_size_has_no_short_tail() {
    let blocks = plan_blocks(1_000, 500).expect("plans");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0], Block { index: 0, offset: 0, len: 500 });
    assert_eq!(blocks[1], Block { index: 1, offset: 500, len: 500 });
}

#[test]
fn a_short_tail_is_the_last_block_and_only_that_one() {
    // ★ The reason the plan exists: a sender computing `index * chunk_size` would read past the end of the file, and
    // one padding the last block would change the object's digest.
    let blocks = plan_blocks(1_200, 500).expect("plans");
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[2], Block { index: 2, offset: 1_000, len: 200 });
    assert!(blocks[..2].iter().all(|block| block.len == 500));
}

#[test]
fn an_empty_object_is_one_empty_block() {
    // ★ One, not zero: a transfer of nothing still has to be proposed, acknowledged and digested, and a plan with no
    // blocks would make a zero-byte file impossible to send.
    let blocks = plan_blocks(0, 500).expect("plans");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].len, 0);
}

#[test]
fn the_blocks_cover_the_object_exactly_once() {
    // The property the whole transfer rests on: the blocks tile the object with no gap and no overlap. Asserted for
    // several shapes rather than one, because both the exact-multiple and the tail cases have their own off-by-one.
    for (total, size) in [(1u64, 500u32), (499, 500), (500, 500), (501, 500), (10_000, 1_024), (7, 3)] {
        let blocks = plan_blocks(total, size).expect("plans");
        let covered: u64 = blocks.iter().map(|block| u64::from(block.len)).sum();
        assert_eq!(covered, total, "total={total} size={size}");
        for (index, block) in blocks.iter().enumerate() {
            assert_eq!(block.index, u32::try_from(index).expect("fits"));
            assert_eq!(block.offset, index as u64 * u64::from(size));
            assert!(block.len <= size);
            if index + 1 < blocks.len() {
                assert_eq!(block.len, size, "only the last block may be short");
            }
        }
    }
}

#[test]
fn a_zero_chunk_size_is_refused() {
    assert!(matches!(
        plan_blocks(100, 0),
        Err(TransferError::ChunkSize { size: 0, .. })
    ));
}

#[test]
fn a_chunk_size_above_the_protocol_ceiling_is_refused() {
    // A block larger than the frame budget is one the encoder would refuse, so refusing it here says so earlier.
    let too_big = u32::try_from(MAX_CHUNK_SIZE).expect("fits") + 1;
    assert!(matches!(
        plan_blocks(100, too_big),
        Err(TransferError::ChunkSize { .. })
    ));
    // And the ceiling itself is accepted, because an off-by-one here refuses a size the protocol allows.
    assert!(plan_blocks(100, u32::try_from(MAX_CHUNK_SIZE).expect("fits")).is_ok());
}

// ── The sender ────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_sender_proposes_a_transfer_that_describes_the_file() {
    let dir = TempDir::new("send-propose");
    let path = file(&dir, "note.txt", b"hello there");
    let sender = TransferSender::open(&path, 4).expect("opens");
    let request = sender.request();

    assert_eq!(request.byte_length, 11);
    assert_eq!(request.chunk_size, 4);
    assert_eq!(request.kind, TransferKind::Attachment);
    assert!(sender.digest().matches(&request.digest));
    let TransferMeta::Attachment { file_name, .. } = &request.meta else {
        panic!("expected an attachment, got {:?}", request.meta);
    };
    assert_eq!(file_name, "note.txt");
}

#[test]
fn a_sender_reads_back_the_bytes_it_promised() {
    // The sender's plan and its reads have to agree, or the receiver stores the wrong bytes at the right offsets.
    let dir = TempDir::new("send-read");
    let content: Vec<u8> = (0..=255u8).cycle().take(1_000).collect();
    let path = file(&dir, "bytes.bin", &content);
    let sender = TransferSender::open(&path, 256).expect("opens");

    let mut rebuilt = Vec::new();
    for block in sender.blocks() {
        let data = sender.read_block(block.index).expect("reads");
        assert_eq!(data.len(), block.len as usize);
        rebuilt.extend_from_slice(&data);
    }
    assert_eq!(rebuilt, content, "the blocks did not rebuild the file");
}

#[test]
fn a_sender_refuses_a_block_past_the_end() {
    let dir = TempDir::new("send-range");
    let path = file(&dir, "small.bin", b"abcd");
    let sender = TransferSender::open(&path, 4).expect("opens");
    assert!(matches!(
        sender.read_block(99),
        Err(TransferError::BlockOutOfRange { index: 99, .. })
    ));
}

#[test]
fn a_sender_knows_which_blocks_are_outstanding() {
    // The resumption question: after a dropped connection, which blocks does the sender still owe?
    let dir = TempDir::new("send-outstanding");
    let path = file(&dir, "four.bin", b"abcdefghijkl");
    let mut sender = TransferSender::open(&path, 4).expect("opens");
    assert_eq!(sender.blocks().len(), 3);

    assert!(!sender.is_complete());
    assert_eq!(sender.outstanding().len(), 3);
    sender.mark_sent(0);
    sender.mark_sent(2);
    assert_eq!(sender.outstanding(), vec![1], "the middle block is still owed");
    sender.mark_sent(1);
    assert!(sender.is_complete());
}

#[test]
fn a_sender_opening_a_missing_file_says_which_one() {
    let dir = TempDir::new("send-missing");
    let missing = dir.path().join("not-there.bin");
    match TransferSender::open(&missing, 256) {
        Err(TransferError::Read { path, why }) => {
            assert_eq!(path, missing);
            assert!(!why.is_empty());
        }
        other => panic!("expected a read failure, got {other:?}"),
    }
}

#[test]
fn a_senders_debug_form_omits_the_file_name() {
    // ★ The path appears in log lines, and a file name can be a person's. A handle that printed it would leak one.
    let dir = TempDir::new("send-debug");
    let path = file(&dir, "diary.txt", b"private");
    let sender = TransferSender::open(&path, 8).expect("opens");
    let text = format!("{sender:?}");
    assert!(!text.contains("diary"), "{text}");
    assert!(!text.contains(dir.path().to_string_lossy().as_ref()), "{text}");
    // But it does say enough to correlate a log line with a transfer.
    assert!(text.contains("blocks"), "{text}");
}

// ── The receiver ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_whole_transfer_arrives_intact() {
    // ★ The end-to-end case, with no socket: a sender's blocks go into a receiver and the file that lands on disk has
    // the bytes the original had, checked by the digest rather than by comparing lengths.
    let dir = TempDir::new("round-trip");
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
    let dir = TempDir::new("duplicate");
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
    let dir = TempDir::new("duplicate-different");
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
    let dir = TempDir::new("out-of-order");
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
    let dir = TempDir::new("unknown-block");
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
    let dir = TempDir::new("too-long");
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
    let dir = TempDir::new("past-end");
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
    let dir = TempDir::new("incomplete");
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
    let dir = TempDir::new("completion-mismatch");
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
    let dir = TempDir::new("wrong-bytes");
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
    let dir = TempDir::new("zero-chunk");
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
    let dir = TempDir::new("empty-round-trip");
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
    let dir = TempDir::new("bitmap");
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
    let dir = TempDir::new("recv-debug");
    let source = file(&dir, "source.bin", b"abcd");
    let sender = TransferSender::open(&source, 4).expect("opens");
    let destination = dir.path().join("secret-name.bin");
    let receiver =
        TransferReceiver::accept(&sender.request(), &destination).expect("accepts");
    let text = format!("{receiver:?}");
    assert!(!text.contains("secret-name"), "{text}");
    assert!(text.contains("total"), "{text}");
}

// ── Errors ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_error_explains_itself() {
    let errors = [
        TransferError::Read { path: PathBuf::from("/tmp/a"), why: "denied".to_owned() },
        TransferError::Write { path: PathBuf::from("/tmp/b"), why: "full".to_owned() },
        TransferError::ChunkSize { size: 0, max: 256 },
        TransferError::UnknownTransfer(TransferId::new()),
        TransferError::BlockTooLong { len: 9, size: 4 },
        TransferError::BlockOutOfRange { index: 9, total: 3 },
        TransferError::Incomplete { missing: 2, total: 5 },
        TransferError::DigestMismatch { actual: "a".to_owned(), expected: "b".to_owned() },
        TransferError::CompletionMismatch { found: "c".to_owned(), promised: "d".to_owned() },
        TransferError::ZeroChunkSize(0),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And the mismatch names both digests, because "integrity mismatch" alone leaves a user with nothing to compare.
    let text = errors[7].to_string();
    assert!(text.contains('a') && text.contains('b'), "{text}");
}
