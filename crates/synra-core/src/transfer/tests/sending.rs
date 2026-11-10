use synra_protocol::session::{TransferKind, TransferMeta};

use crate::test_support::{file, temp_dir};

use super::super::{TransferError, TransferSender};

#[test]
fn a_sender_proposes_a_transfer_that_describes_the_file() {
    let dir = temp_dir("send-propose");
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
    let dir = temp_dir("send-read");
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
    let dir = temp_dir("send-range");
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
    let dir = temp_dir("send-outstanding");
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
    let dir = temp_dir("send-missing");
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
    let dir = temp_dir("send-debug");
    let path = file(&dir, "diary.txt", b"private");
    let sender = TransferSender::open(&path, 8).expect("opens");
    let text = format!("{sender:?}");
    assert!(!text.contains("diary"), "{text}");
    assert!(!text.contains(dir.path().to_string_lossy().as_ref()), "{text}");
    // But it does say enough to correlate a log line with a transfer.
    assert!(text.contains("blocks"), "{text}");
}
