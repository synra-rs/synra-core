use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use synra_protocol::ids::TransferId;
use synra_protocol::session::{ProgressBitmap, TransferKind, TransferMeta, TransferRequest};

use super::digest::ObjectDigest;
use super::error::TransferError;
use super::plan::{Block, plan_blocks};

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

    /// Whether this side has already written a block to the link.
    ///
    /// # Why a sender needs to ask
    ///
    /// Because a receiver's report says which blocks it **lacks**, and the moment a report is sent, every block still in
    /// flight is one it lacks. Queueing those again puts a duplicate of each on the wire; the receiver absorbs it as
    /// already-held, reports the rest as still missing, and the queue never drains — a 5 MB file ran to the sender's
    /// 300-second deadline that way. So a block is queued only if it is reported missing **and** this side has not written
    /// it, and this is how the second half of that is asked.
    #[must_use]
    pub fn has_sent(&self, index: u32) -> bool {
        self.sent.contains(index)
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
