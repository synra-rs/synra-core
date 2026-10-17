//! What the send loop does, without a peer.

use super::{SendBlocksError, send_blocks};
use crate::transfer::{DEFAULT_CHUNK_SIZE, TransferSender};

/// A sender over a file of these bytes, in a scratch directory of its own.
fn sender_of(label: &str, bytes: &[u8]) -> (std::path::PathBuf, TransferSender) {
    let path = std::env::temp_dir().join(format!("synra-send-{label}-{}", std::process::id()));
    std::fs::write(&path, bytes).expect("a file");
    let sender = TransferSender::open(&path, DEFAULT_CHUNK_SIZE).expect("a sender");
    (path, sender)
}

#[test]
fn every_block_is_sent_once_and_progress_is_reported() {
    // ★ Three claims: the bytes arrive complete, each block goes out once, and the progress numbers end at the total — a
    // progress bar that stops at 80% is the failure this asserts against.
    let (path, mut sender) = sender_of("all", &vec![7u8; 3 * DEFAULT_CHUNK_SIZE as usize + 10]);
    let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut progress: Vec<(u32, u32)> = Vec::new();

    send_blocks(
        &mut sender,
        |index, data| {
            chunks.push((index, data.to_vec()));
            Ok::<(), std::convert::Infallible>(())
        },
        |done, total| progress.push((done, total)),
    )
    .expect("it sends");

    let total = u32::try_from(sender.blocks().len()).expect("four blocks");
    assert_eq!(total, 4, "three whole chunks and a remainder");
    assert_eq!(chunks.len(), 4, "each block once");
    assert_eq!(progress.last(), Some(&(total, total)), "progress ends at the total");
    let joined: Vec<u8> = chunks.into_iter().flat_map(|(_, data)| data).collect();
    assert_eq!(joined.len(), 3 * DEFAULT_CHUNK_SIZE as usize + 10, "all the bytes");

    let _ = std::fs::remove_file(path);
}

#[test]
fn a_refused_block_stops_the_loop_and_is_not_marked_sent() {
    // ★ The order in the loop is read → send → mark. A refusal must leave the block outstanding, or a retry would skip the
    // very block that never left.
    let (path, mut sender) = sender_of("refused", &vec![1u8; 2 * DEFAULT_CHUNK_SIZE as usize]);

    let refused = send_blocks(&mut sender, |_, _| Err("the link is closed"), |_, _| {}).expect_err("refused");

    assert!(matches!(refused, SendBlocksError::Send("the link is closed")));
    assert_eq!(sender.outstanding().len(), 2, "nothing was marked sent");

    let _ = std::fs::remove_file(path);
}
