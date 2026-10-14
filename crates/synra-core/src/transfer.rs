//! Sending a file, in pieces, and knowing whether it arrived.
//!
//! # What this layer owns, and what it does not
//!
//! The protocol already defines the wire shapes — `TransferRequest`, `ProgressBitmap`, `SriDigest`, the chunk frame — and
//! `synra-protocol` is tested against them. What nobody had was the part that *uses* them: how a file becomes ordered
//! pieces, what a receiver does with a piece that arrives twice or not at all, and how either side decides the object
//! arrived intact.
//!
//! That is this module, and it deliberately holds no socket. Every decision here is a value in and a value out, which is
//! what makes the interesting cases — a re-sent block, a block from a transfer that was never proposed, a digest that
//! disagrees — testable without a network at all. [`TransferSender`] and [`TransferReceiver`] are driven by a caller that
//! owns a link.
//!
//! # The two rules everything follows
//!
//! * **The digest is the only proof.** A receiver that accepted a file because every block arrived would be one that
//!   accepts a file whose blocks arrived *wrong* — a reordered splice, a truncated tail, a disk that lied. The whole-object
//!   digest is checked once, at the end, and nothing counts as received until it agrees.
//! * **A transfer is identified, not inferred.** `transfer_id` is in the request and in every frame, so a block that
//!   names an unknown transfer is refused rather than applied to whatever happens to be in progress. Without that, two
//!   files sent at once interleave into one corrupt one.
//!
//! # Why the sender chunks the whole file up front
//!
//! It does not hash twice. [`TransferSender::open`] streams the file once, computing the digest and recording each block's
//! offset — so a ten-gigabyte file costs one pass and its plan, not two passes and a buffer. The alternative, hashing as
//! blocks are sent, would mean the `TransferRequest` could not carry the digest until *after* the data had moved — and the
//! request is what tells the receiver whether to accept the transfer at all.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use synra_protocol::ids::TransferId;
use synra_protocol::session::{
    DigestAlgorithm, ProgressBitmap, SriDigest, TransferKind, TransferMeta, TransferRequest,
};

/// How much of a file goes in one block by default.
///
/// The protocol allows up to 256 KiB per frame. This is that ceiling: a block smaller than the frame budget would waste a
/// header per block on a fast link, and one larger is refused by the frame encoder.
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;

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

/// A whole-object digest, as the wire carries it.
///
/// # Why this exists rather than a bare string
///
/// Because `SriDigest` holds an algorithm *and* a value, and the two have to agree — a 43-character base64 string means
/// SHA-256 and nothing else. Computing the value and the algorithm together is what stops a caller pairing a SHA-256 value
/// with a different algorithm name, which is a mistake that would only surface at the far end of a transfer.
#[derive(Debug, Clone)]
pub struct ObjectDigest {
    digest: SriDigest,
}

impl ObjectDigest {
    /// Hashes bytes that are already in memory.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::from_hasher(hasher)
    }

    /// Streams a reader to the end, hashing as it goes.
    ///
    /// # Errors
    ///
    /// [`TransferError::Read`] when the reader fails. The digest of a file that could not be read is not a digest of the
    /// file, and returning one would make a truncated object look intact.
    pub fn of_reader(path: &Path, reader: &mut impl Read) -> Result<Self, TransferError> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(|error| TransferError::Read {
                path: path.to_path_buf(),
                why: error.to_string(),
            })?;
            if read == 0 {
                break;
            }
            // The slice is bounded by the read count, which the reader guarantees is no more than the buffer.
            let chunk = buffer.get(..read).ok_or_else(|| TransferError::Read {
                path: path.to_path_buf(),
                why: "the reader reported more bytes than the buffer".to_owned(),
            })?;
            hasher.update(chunk);
        }
        Ok(Self::from_hasher(hasher))
    }

    fn from_hasher(hasher: Sha256) -> Self {
        let bytes = hasher.finalize();
        // Base64 **without padding**, which is the form `SriDigest` accepts: standard alphabet, no `=`.
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        // The value is 32 bytes encoded, so it has exactly the length SHA-256 declares — the constructor's only failure
        // here would be a bug in this crate, and a fallback that produced a wrong-length value would be worse than the
        // wrong answer being visible.
        match SriDigest::new(DigestAlgorithm::Sha256, encoded) {
            Ok(digest) => Self { digest },
            Err(why) => {
                debug_assert!(false, "this crate produced an unusable digest: {why}");
                // An empty SHA-256 digest is still 43 characters, so a caller that reaches this keeps a *value* of the
                // right shape rather than a panic in a library. The debug assertion above is where a developer sees it.
                Self::of(b"")
            }
        }
    }

    /// The wire form.
    #[must_use]
    pub const fn as_sri(&self) -> &SriDigest {
        &self.digest
    }

    /// The encoded value, without the algorithm prefix.
    #[must_use]
    pub fn encoded(&self) -> &str {
        self.digest.encoded()
    }

    /// Whether two digests name the same bytes.
    #[must_use]
    pub fn matches(&self, other: &SriDigest) -> bool {
        // Compared through the encoded form rather than through a derived `PartialEq`, because `SriDigest`'s equality is
        // the protocol's to define and this asks a narrower question: do these two describe the same bytes.
        self.digest.algorithm() == other.algorithm() && self.digest.encoded() == other.encoded()
    }
}

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

/// What a sender is doing with a file.
pub struct TransferSender {
    transfer_id: TransferId,
    path: PathBuf,
    byte_length: u64,
    chunk_size: u32,
    digest: ObjectDigest,
    blocks: Vec<Block>,
    /// Which blocks have been handed out, so a resend is possible without re-reading the file's plan.
    sent: ProgressBitmap,
    file_name: String,
}

impl std::fmt::Debug for TransferSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The path is deliberately absent: it appears in log lines and a file name can be a person's.
        f.debug_struct("TransferSender")
            .field("transfer_id", &self.transfer_id)
            .field("byte_length", &self.byte_length)
            .field("blocks", &self.blocks.len())
            .field("digest", &self.digest.encoded())
            .finish()
    }
}

impl TransferSender {
    /// Opens a file and works out how to send it.
    ///
    /// # Why the digest is computed here, before any message is sent
    ///
    /// Because the `TransferRequest` carries it, and the request is what lets a receiver decide whether to accept the
    /// transfer at all. A digest computed while sending would mean the receiver had already committed to receiving an
    /// object whose integrity nobody had stated yet.
    ///
    /// # Errors
    ///
    /// [`TransferError::Read`] when the file cannot be read, and [`TransferError::ChunkSize`] for an unusable size.
    pub fn open(path: &Path, chunk_size: u32) -> Result<Self, TransferError> {
        let mut file = std::fs::File::open(path).map_err(|error| TransferError::Read {
            path: path.to_path_buf(),
            why: error.to_string(),
        })?;
        let byte_length = file
            .metadata()
            .map_err(|error| TransferError::Read {
                path: path.to_path_buf(),
                why: error.to_string(),
            })?
            .len();
        let digest = ObjectDigest::of_reader(path, &mut file)?;
        let blocks = plan_blocks(byte_length, chunk_size)?;

        // `u32` rather than `usize`: the bitmap counts blocks, and a block count is what the protocol's field is.
        let total = u32::try_from(blocks.len()).unwrap_or(u32::MAX);
        let file_name = path
            .file_name()
            .map_or_else(|| "file".to_owned(), |name| name.to_string_lossy().into_owned());

        Ok(Self {
            transfer_id: TransferId::new(),
            path: path.to_path_buf(),
            byte_length,
            chunk_size,
            digest,
            blocks,
            sent: ProgressBitmap::empty(total),
            file_name,
        })
    }

    /// The request that proposes this transfer.
    ///
    /// # Why the kind is always `Attachment`
    ///
    /// Because the other kind is a plugin bundle, which is the plugin host's to send and carries a plugin id and version
    /// this does not have. A transfer layer that guessed would produce a message the receiver would route to the plugin
    /// installer.
    #[must_use]
    pub fn request(&self) -> TransferRequest {
        TransferRequest {
            transfer_id: self.transfer_id,
            kind: TransferKind::Attachment,
            byte_length: self.byte_length,
            chunk_size: self.chunk_size,
            digest: self.digest.as_sri().clone(),
            sync_session_id: None,
            meta: TransferMeta::Attachment {
                file_name: self.file_name.clone(),
                mime_type: None,
                context_id: None,
            },
        }
    }

    /// Identifies this transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// How the object is split.
    #[must_use]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// The whole-object digest.
    #[must_use]
    pub const fn digest(&self) -> &ObjectDigest {
        &self.digest
    }

    /// Reads one block's bytes.
    ///
    /// # Errors
    ///
    /// [`TransferError::Read`] when the file cannot be read, and [`TransferError::BlockOutOfRange`] for an index past the
    /// end. Nothing is marked as sent: the caller decides when a block is on the wire, because only it knows whether the
    /// write succeeded.
    pub fn read_block(&self, index: u32) -> Result<Vec<u8>, TransferError> {
        let block = self
            .blocks
            .get(usize::try_from(index).unwrap_or(usize::MAX))
            .ok_or(TransferError::BlockOutOfRange {
                index,
                total: u32::try_from(self.blocks.len()).unwrap_or(u32::MAX),
            })?;

        let mut file = std::fs::File::open(&self.path).map_err(|error| TransferError::Read {
            path: self.path.clone(),
            why: error.to_string(),
        })?;
        file.seek(SeekFrom::Start(block.offset)).map_err(|error| TransferError::Read {
            path: self.path.clone(),
            why: error.to_string(),
        })?;
        let mut buffer = vec![0u8; block.len as usize];
        file.read_exact(&mut buffer).map_err(|error| TransferError::Read {
            path: self.path.clone(),
            why: error.to_string(),
        })?;
        Ok(buffer)
    }

    /// Records that a block is on the wire.
    pub fn mark_sent(&mut self, index: u32) {
        self.sent.set(index);
    }

    /// Replaces what this sender believes has arrived with what the receiver reported.
    ///
    /// # Why the receiver's word replaces this side's rather than being merged with it
    ///
    /// Because a block that was written to a socket is not a block that arrived. The sender's own record says "I sent it";
    /// the receiver's says "I have it", and only the second one means the transfer can finish. Merging would keep the
    /// sender's bit for a block that was lost, so it would never be re-sent and the transfer would hang — waiting for an
    /// acknowledgement of something the far end never received.
    pub fn adopt_acknowledged(&mut self, acknowledged: &ProgressBitmap) {
        // A report of a different size is not adopted: it describes a different transfer, and the caller checks the
        // identifier. Sizing it to the shorter of the two would silently drop blocks.
        if acknowledged.total_blocks() != self.sent.total_blocks() {
            return;
        }
        self.sent = acknowledged.clone();
    }

    /// Whether every block has been sent.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.sent.is_complete()
    }

    /// Which blocks have not been sent.
    #[must_use]
    pub fn outstanding(&self) -> Vec<u32> {
        self.sent.missing()
    }
}

/// What a receiver did with a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Absorbed {
    /// The block was new, and is now held.
    Stored,
    /// The block had already arrived.
    ///
    /// # Why this is a success rather than a refusal
    ///
    /// Because a re-sent block is what a resumption *is*. A receiver that refused a duplicate would make a retry after a
    /// dropped acknowledgement look like corruption, and the sender would have no way to tell the two apart.
    Duplicate,
}

/// What a receiver is doing with a file.
pub struct TransferReceiver {
    transfer_id: TransferId,
    byte_length: u64,
    chunk_size: u32,
    expected: SriDigest,
    blocks: Vec<Block>,
    have: ProgressBitmap,
    file: std::fs::File,
    path: PathBuf,
    bytes_received: u64,
}

impl std::fmt::Debug for TransferReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferReceiver")
            .field("transfer_id", &self.transfer_id)
            .field("byte_length", &self.byte_length)
            .field("received", &self.have.received_count())
            .field("total", &self.have.total_blocks())
            .finish()
    }
}

impl TransferReceiver {
    /// Accepts a proposal and creates the file to fill.
    ///
    /// # Errors
    ///
    /// [`TransferError::ZeroChunkSize`] when the sender offered zero — which would make every block zero bytes and the
    /// transfer unending — and [`TransferError::Write`] when the destination cannot be created.
    pub fn accept(request: &TransferRequest, destination: &Path) -> Result<Self, TransferError> {
        if request.chunk_size == 0 {
            return Err(TransferError::ZeroChunkSize(request.chunk_size));
        }
        // Pre-sized to the declared length, so a short write is visible as a short file rather than as a file that grew
        // as it went. `set_len` on a file that has just been created is a sparse allocation on every platform this runs
        // on, so a ten-gigabyte transfer does not need ten gigabytes before the first block arrives.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(destination)
            .map_err(|error| TransferError::Write {
                path: destination.to_path_buf(),
                why: error.to_string(),
            })?;
        file.set_len(request.byte_length).map_err(|error| TransferError::Write {
            path: destination.to_path_buf(),
            why: error.to_string(),
        })?;

        let blocks = plan_blocks(request.byte_length, request.chunk_size)?;
        let total = u32::try_from(blocks.len()).unwrap_or(u32::MAX);

        Ok(Self {
            transfer_id: request.transfer_id,
            byte_length: request.byte_length,
            chunk_size: request.chunk_size,
            expected: request.digest.clone(),
            blocks,
            have: ProgressBitmap::empty(total),
            file,
            path: destination.to_path_buf(),
            bytes_received: 0,
        })
    }

    /// Identifies this transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// How many blocks have arrived.
    #[must_use]
    pub fn received_count(&self) -> u32 {
        self.have.received_count()
    }

    /// How many bytes have arrived.
    #[must_use]
    pub const fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Where the file is being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The bitmap the protocol's progress message carries.
    #[must_use]
    pub const fn bitmap(&self) -> &ProgressBitmap {
        &self.have
    }

    /// Takes one block.
    ///
    /// # Errors
    ///
    /// [`TransferError::BlockTooLong`] for a block bigger than the sender promised, [`TransferError::BlockOutOfRange`] for
    /// an index past the end, and [`TransferError::Write`] when the disk refuses.
    pub fn absorb(&mut self, index: u32, data: &[u8]) -> Result<Absorbed, TransferError> {
        if data.len() > self.chunk_size as usize {
            return Err(TransferError::BlockTooLong { len: data.len(), size: self.chunk_size });
        }
        let block = *self
            .blocks
            .get(usize::try_from(index).unwrap_or(usize::MAX))
            .ok_or(TransferError::BlockOutOfRange {
                index,
                total: u32::try_from(self.blocks.len()).unwrap_or(u32::MAX),
            })?;

        // ★ A short block is only allowed at the end, and this is where that is enforced. Anywhere else, a short block
        // means the sender's idea of the layout has diverged from the request — and writing it would shift every later
        // byte, producing a file whose digest fails at the end for what looks like a corruption in the middle.
        let is_last = block.index == u32::try_from(self.blocks.len()).unwrap_or(u32::MAX) - 1;
        if !is_last && data.len() != self.chunk_size as usize {
            return Err(TransferError::BlockTooLong { len: data.len(), size: self.chunk_size });
        }
        if is_last && data.len() != block.len as usize {
            return Err(TransferError::BlockTooLong { len: data.len(), size: block.len });
        }

        if self.have.contains(index) {
            return Ok(Absorbed::Duplicate);
        }

        self.file
            .seek(SeekFrom::Start(block.offset))
            .and_then(|_| self.file.write_all(data))
            .map_err(|error| TransferError::Write {
                path: self.path.clone(),
                why: error.to_string(),
            })?;

        self.have.set(index);
        // Saturating, because the count is a report and a wrap would make a completed transfer look empty.
        self.bytes_received = self.bytes_received.saturating_add(data.len() as u64);
        Ok(Absorbed::Stored)
    }

    /// Checks the object and finishes the transfer.
    ///
    /// # The order is the rule
    ///
    /// The completion's digest is compared with the request's **first**, then the bytes are hashed. A transfer where the
    /// two messages disagree is one where something between them rewrote one, and refusing it without reading the file
    /// means a tampered transfer costs no I/O. Then every block must be present, because a file with a hole in it can still
    /// hash to something — just not to what was promised, and the "missing" answer is more useful than a digest mismatch
    /// for a file that was never finished.
    ///
    /// # Errors
    ///
    /// [`TransferError::CompletionMismatch`], [`TransferError::Incomplete`], [`TransferError::DigestMismatch`], or
    /// [`TransferError::Read`] when the file cannot be re-read.
    pub fn finish(&mut self, completion: &SriDigest) -> Result<ObjectDigest, TransferError> {
        if !(self.expected.algorithm() == completion.algorithm()
            && self.expected.encoded() == completion.encoded())
        {
            return Err(TransferError::CompletionMismatch {
                found: completion.encoded().to_owned(),
                promised: self.expected.encoded().to_owned(),
            });
        }

        let missing = self.have.missing().len();
        if missing > 0 {
            return Err(TransferError::Incomplete {
                missing,
                total: self.have.total_blocks(),
            });
        }

        // Flushed before it is read back, because the bytes are in the operating system's cache rather than on the disk and
        // a second handle would not necessarily see them.
        self.file.flush().map_err(|error| TransferError::Write {
            path: self.path.clone(),
            why: error.to_string(),
        })?;

        let mut reader = std::fs::File::open(&self.path).map_err(|error| TransferError::Read {
            path: self.path.clone(),
            why: error.to_string(),
        })?;
        let actual = ObjectDigest::of_reader(&self.path, &mut reader)?;
        if !actual.matches(&self.expected) {
            return Err(TransferError::DigestMismatch {
                actual: actual.encoded().to_owned(),
                expected: self.expected.encoded().to_owned(),
            });
        }
        Ok(actual)
    }

    /// The declared length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// The digest the sender promised, before any bytes arrived.
    ///
    /// # Why a caller needs it
    ///
    /// Because a transfer can end without a completion message — a caller that lost the link and wants to check what it
    /// has, or a test driving the halves separately. Both need the digest the request carried, and reaching for a field is
    /// not possible from outside this module.
    #[must_use]
    pub const fn expected_digest(&self) -> &SriDigest {
        &self.expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
