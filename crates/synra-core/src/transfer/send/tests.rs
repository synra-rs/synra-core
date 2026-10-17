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
fn the_blocks_arrive_over_a_real_link() {
    // ★ The end-to-end shape without a socket: two `MemoryStream`s behave as one connection, so the sender's loop, the frame
    // encoder and the receiver's decoder all run for real. A send that only ever ran against a closure could pass while
    // producing frames no peer could read.
    //
    // ★ Capacity, not a deadline, is what this test needs: the default pipe holds 64 KiB per direction, and sending before
    // reading fills it, so the write blocks and the test hangs. Room for both blocks is the fix; a read deadline would only
    // have turned a deadlock into a timeout.
    use crate::link::Inbound;
    use crate::link::PeerLink;
    use crate::link::memory::MemoryStream;
    use crate::peer::Flags;
    use synra_protocol::handshake::Agreed;
    use synra_protocol::ids::DeviceId;

    let (near, far) = MemoryStream::pair_with_capacity(4 * 1024 * 1024);
    let agreed = Agreed { common: Vec::new(), missing_required: Vec::new() };
    let local = DeviceId::new();
    let peer = DeviceId::new();
    let mut sending = PeerLink::new(near, local, peer, agreed.clone(), Flags::no_timeout());
    let mut receiving = PeerLink::new(far, peer, local, agreed, Flags::no_timeout());

    let (path, mut sender) = sender_of("memory", &vec![9u8; 2 * DEFAULT_CHUNK_SIZE as usize]);
    let total = sender.blocks().len();

    send_blocks(&mut sender, |index, data| sending.send_chunk(index, data), |_, _| {}).expect("it sends");

    for expected in 0..total {
        match receiving.receive_inbound().expect("a block") {
            Inbound::Block { chunk_id, .. } => assert_eq!(chunk_id as usize, expected, "blocks arrive in order"),
            other => panic!("expected a block, got {other:?}"),
        }
    }

    let _ = std::fs::remove_file(path);
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
