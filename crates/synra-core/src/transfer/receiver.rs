use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use synra_protocol::ids::TransferId;
use synra_protocol::session::{ProgressBitmap, SriDigest, TransferRequest};

use super::digest::ObjectDigest;
use super::error::TransferError;
use super::plan::{Block, plan_blocks};

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
