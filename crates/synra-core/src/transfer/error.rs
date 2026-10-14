use std::path::PathBuf;

use synra_protocol::ids::TransferId;

/// Why a transfer could not proceed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// The file could not be read.
    #[error("could not read {}: {why}", path.display())]
    Read {
        /// Which file.
        path: PathBuf,
        /// What the operating system said.
        why: String,
    },

    /// The file could not be written.
    #[error("could not write {}: {why}", path.display())]
    Write {
        /// Which file.
        path: PathBuf,
        /// What the operating system said.
        why: String,
    },

    /// The proposed chunk size is outside what the protocol allows.
    #[error("a chunk size of {size} is outside 1..={max}")]
    ChunkSize {
        /// What was asked for.
        size: u32,
        /// What the protocol allows.
        max: u32,
    },

    /// A block named a transfer this receiver is not running.
    #[error("block for transfer {0}, which is not in progress")]
    UnknownTransfer(TransferId),

    /// A block was longer than the transfer's declared chunk size.
    ///
    /// # Why this is refused rather than trimmed
    ///
    /// Because the chunk size is the sender's promise about how it will split the object, and the receiver checks the
    /// sender keeps its word. A long block means the two disagree about where every later block *starts*, so accepting it
    /// would place every subsequent byte at the wrong offset — and the digest would fail at the end for a reason that
    /// looked like corruption rather than like a broken promise.
    #[error("a block of {len} bytes exceeds the agreed chunk size of {size}")]
    BlockTooLong {
        /// How long the block was.
        len: usize,
        /// What was agreed.
        size: u32,
    },

    /// A block's sequence number is past the end of the object.
    #[error("block {index} is past the end of a {total}-block transfer")]
    BlockOutOfRange {
        /// Which block.
        index: u32,
        /// How many there are.
        total: u32,
    },

    /// The object is not all there yet.
    #[error("{missing} of {total} blocks are still missing")]
    Incomplete {
        /// How many.
        missing: usize,
        /// Out of how many.
        total: u32,
    },

    /// The bytes did not match what was promised.
    ///
    /// The failure a user sees as `integrity_mismatch`, and the only one that means the data is untrustworthy rather than
    /// merely absent.
    #[error("the object hashed to {actual} and the sender promised {expected}")]
    DigestMismatch {
        /// What arrived.
        actual: String,
        /// What was declared.
        expected: String,
    },

    /// The complete message disagreed with the request.
    ///
    /// # Why a second digest is checked at all
    ///
    /// Because the request and the completion are two separate messages, and a transfer where they disagree is one where
    /// something between them rewrote one of the two. The completion's digest is compared with the request's **before**
    /// the bytes are hashed, so a transfer that was tampered with is refused without reading the file.
    #[error("the completion names {found} and the request promised {promised}")]
    CompletionMismatch {
        /// What the completion said.
        found: String,
        /// What the request said.
        promised: String,
    },

    /// The chunk size in the request is unusable.
    #[error("the sender offered a chunk size of {0}, which is zero")]
    ZeroChunkSize(u32),
}
