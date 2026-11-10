use serde::{Deserialize, Serialize};

use crate::ids::TransferId;
use crate::limits;
use super::types::SriDigest;

/// Which blocks the receiver has, as a bitmap.
///
/// A bitmap rather than a list of indices: a list of a hundred thousand indices is a hundred
/// thousand numbers, and the same information in bits is twelve kilobytes. It also makes "which
/// blocks am I missing" a bitwise operation rather than a set difference.
///
/// # Bit order
///
/// Little-endian *within each byte*: block `n` lives in byte `n / 8`, at bit `n % 8`, with bit 0 the
/// least significant. Chosen so that comparing two bitmaps is a plain `u8` operation per byte.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProgressBitmap {
    bytes: Vec<u8>,
    /// Total blocks the transfer comprises, so trailing padding bits are never mistaken for blocks.
    total_blocks: u32,
}

impl ProgressBitmap {
    /// A bitmap for a transfer of `total_blocks` blocks, with none received.
    #[must_use]
    pub fn empty(total_blocks: u32) -> Self {
        let byte_len = total_blocks.div_ceil(8) as usize;
        Self { bytes: vec![0; byte_len], total_blocks }
    }

    /// A bitmap with every block marked received.
    #[must_use]
    pub fn full(total_blocks: u32) -> Self {
        let mut bitmap = Self::empty(total_blocks);
        for block in 0..total_blocks {
            bitmap.set(block);
        }
        bitmap
    }

    /// Total blocks this bitmap covers.
    #[must_use]
    pub const fn total_blocks(&self) -> u32 {
        self.total_blocks
    }

    /// Marks a block received. A block beyond the total is ignored.
    pub fn set(&mut self, block: u32) {
        if block >= self.total_blocks {
            return;
        }
        let index = (block / 8) as usize;
        let bit = (block % 8) as u8;
        if let Some(byte) = self.bytes.get_mut(index) {
            *byte |= 1 << bit;
        }
    }

    /// Whether a block has been received.
    #[must_use]
    pub fn contains(&self, block: u32) -> bool {
        if block >= self.total_blocks {
            return false;
        }
        let index = (block / 8) as usize;
        let bit = (block % 8) as u8;
        self.bytes.get(index).is_some_and(|byte| byte & (1 << bit) != 0)
    }

    /// How many blocks have been received.
    #[must_use]
    pub fn received_count(&self) -> u32 {
        let full_bytes = (self.total_blocks / 8) as usize;
        let mut count: u32 = self
            .bytes
            .iter()
            .take(full_bytes)
            .map(|byte| byte.count_ones())
            .sum();

        // The partial byte needs masking, or its padding bits would be counted as blocks — and a
        // transfer would appear complete before it was.
        let remainder = self.total_blocks % 8;
        if remainder != 0
            && let Some(byte) = self.bytes.get(full_bytes)
        {
            let mask = (1u8 << remainder) - 1;
            count += (byte & mask).count_ones();
        }
        count
    }

    /// Whether every block has been received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received_count() == self.total_blocks
    }

    /// The blocks still missing, in ascending order.
    ///
    /// What a sender retransmits. The caller decides how many losses are worth patching: a transfer
    /// that has lost most of its blocks is better restarted than repaired.
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        (0..self.total_blocks)
            .filter(|block| !self.contains(*block))
            .collect()
    }

    /// The highest block index this bitmap holds, or `None` when it holds none.
    ///
    /// # Why a sender needs this
    ///
    /// Because a report is a snapshot and names as "missing" every block still crossing the network. A block **below** the
    /// highest one the receiver holds has been passed over by an in-order reader, so it is genuinely lost and worth
    /// rewriting; one above it is merely late. Without the distinction a sender rewrites what is already in flight — a
    /// 5 MB transfer logged 54 duplicate blocks that way.
    #[must_use]
    pub fn highest(&self) -> Option<u32> {
        (0..self.total_blocks).rev().find(|block| self.contains(*block))
    }

    /// The raw bytes, for the wire.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Rebuilds a bitmap from bytes received on the wire.
    ///
    /// # Errors
    ///
    /// A description if the length disagrees with the block count, which would mean the two sides
    /// differed about the transfer's size.
    pub fn from_bytes(bytes: Vec<u8>, total_blocks: u32) -> Result<Self, &'static str> {
        let expected = total_blocks.div_ceil(8) as usize;
        if bytes.len() != expected {
            return Err("progress bitmap length does not match the block count");
        }
        Ok(Self { bytes, total_blocks })
    }
}

/// Which blocks a transfer has received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferProgress {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// The bitmap, base64 on the wire.
    pub received: Vec<u8>,
    /// Total blocks, repeated so the receiver can check the two agree.
    pub total_blocks: u32,
    /// Bytes received, for a progress display that does not have to count bits.
    pub bytes_received: u64,
}

/// The sender's assertion that a transfer is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferComplete {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// The digest, repeated. The receiver compares it with the one in the request rather than
    /// trusting the later message alone.
    pub digest: SriDigest,
}

/// Why a transfer ended badly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransferAbortReason {
    /// The user stopped it.
    UserCancelled,
    /// The bytes did not match the declared digest.
    DigestMismatch,
    /// The object is larger than the receiver accepts.
    TooLarge,
    /// A read or write failed.
    IoError,
    /// No progress for longer than the idle timeout.
    IdleTimeout,
    /// The transfer ran longer than the total timeout.
    TotalTimeout,
    /// The receiver declined.
    PeerRejected,
}

impl TransferAbortReason {
    /// Whether restarting could help.
    ///
    /// The distinction drives whether the interface offers a retry button: offering one for a digest
    /// mismatch would invite the user to repeat a failure that will happen again.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::IoError | Self::IdleTimeout | Self::TotalTimeout)
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCancelled => "user_cancelled",
            Self::DigestMismatch => "digest_mismatch",
            Self::TooLarge => "too_large",
            Self::IoError => "io_error",
            Self::IdleTimeout => "idle_timeout",
            Self::TotalTimeout => "total_timeout",
            Self::PeerRejected => "peer_rejected",
        }
    }
}

/// A transfer being given up on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferAbort {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// Why.
    pub reason: TransferAbortReason,
}

/// The sliding window a transfer keeps in flight.
///
/// A window rather than a block-at-a-time loop because the loop's throughput is bounded by the
/// round-trip time rather than by the link. A 5 MB object in 64 KiB blocks is eighty round trips; at
/// 2 ms each that is a sixth of a second spent waiting instead of sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferWindow {
    /// How many blocks may be unacknowledged at once.
    pub in_flight: u32,
    /// The block size in bytes.
    pub chunk_size: u32,
}

impl Default for TransferWindow {
    fn default() -> Self {
        Self { in_flight: 32, chunk_size: limits::MAX_CHUNK_LEN as u32 }
    }
}

impl TransferWindow {
    /// Checks the window and block size are usable.
    ///
    /// # Errors
    ///
    /// A description of what is wrong.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.in_flight == 0 {
            return Err("in_flight must be non-zero, or no data is ever sent");
        }
        if self.chunk_size == 0 {
            return Err("chunk_size must be non-zero");
        }
        if self.chunk_size as usize > limits::MAX_CHUNK_LEN {
            return Err("chunk_size exceeds the maximum block size");
        }
        Ok(())
    }

    /// How much data is in flight at most.
    #[must_use]
    pub const fn bytes_in_flight(&self) -> u64 {
        self.in_flight as u64 * self.chunk_size as u64
    }

    /// How many blocks an object of `byte_length` needs.
    #[must_use]
    pub const fn block_count(&self, byte_length: u64) -> u32 {
        // Rounded up: a partial trailing block is still a block, and rounding down would drop it.
        // The cast is safe because a transfer with more than 2^32 blocks is far beyond what is
        // accepted.
        byte_length.div_ceil(self.chunk_size as u64) as u32
    }
}
