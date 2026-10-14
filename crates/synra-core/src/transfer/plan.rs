use super::error::TransferError;

/// How much of a file goes in one block by default.
///
/// The protocol allows up to 256 KiB per frame. This is that ceiling: a block smaller than the frame budget would waste a
/// header per block on a fast link, and one larger is refused by the frame encoder.
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;

/// Where a block sits in an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    /// Which block, from zero.
    pub index: u32,
    /// Where its bytes start.
    pub offset: u64,
    /// How many bytes it holds. The last block is usually short.
    pub len: u32,
}

impl Block {
    /// Where the block ends.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.offset + self.len as u64
    }
}

/// Splits an object into blocks.
///
/// # Why the plan is computed rather than derived per block
///
/// Because the last block is short, and a sender that computed offsets as `index * chunk_size` would read past the end of
/// the file for it — or send a full-length block and pad the object, which changes its digest. The plan is where the
/// short tail is decided, once.
///
/// # Errors
///
/// [`TransferError::ChunkSize`] when the size is zero or above the protocol's ceiling.
pub fn plan_blocks(byte_length: u64, chunk_size: u32) -> Result<Vec<Block>, TransferError> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE as u32 {
        return Err(TransferError::ChunkSize {
            size: chunk_size,
            max: MAX_CHUNK_SIZE as u32,
        });
    }
    // A size that is a plain `u32::try_from` cannot fail.
    let size = u64::from(chunk_size);
    // Enough blocks for the whole object, with at least one so an empty file is still a transfer rather than nothing.
    let count = byte_length.div_ceil(size).max(1);

    let mut blocks = Vec::new();
    for index in 0..count {
        let offset = index * size;
        // The tail: whatever is left, which is a full block for every block but the last unless the object divides
        // exactly.
        let remaining = byte_length.saturating_sub(offset);
        let len = remaining.min(size);
        // A `u32` conversion that cannot fail: `len` is at most `size`, which is a `u32` by type.
        let len = u32::try_from(len).unwrap_or(chunk_size);
        // A block count beyond what the sequence number can address is a file no protocol message could describe, and
        // `u32` blocks of 256 KiB is a petabyte — so this is a refusal rather than a truncation.
        let Ok(index) = u32::try_from(index) else {
            return Err(TransferError::ChunkSize { size: chunk_size, max: MAX_CHUNK_SIZE as u32 });
        };
        blocks.push(Block { index, offset, len });
    }
    Ok(blocks)
}

/// The protocol's own ceiling on one block, re-exported so a caller need not reach into two crates.
pub const MAX_CHUNK_SIZE: usize = synra_protocol::limits::MAX_CHUNK_LEN;
