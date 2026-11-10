use super::super::{Block, MAX_CHUNK_SIZE, TransferError, plan_blocks};

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
