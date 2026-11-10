use super::*;

/// Why a sync was refused by the receiver.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// A chunk arrived for a round this device is not in.
    ///
    /// ★ The isolation rule. A chunk from a previous round has the same index and different bytes, and absorbing one
    /// would corrupt the package in a way no digest catches until the end — or, worse, in a way it does.
    #[error("a chunk belongs to session {theirs} and this device is in {ours}")]
    WrongSession {
        /// The session the chunk named.
        theirs: String,
        /// The session this device is in.
        ours: String,
    },

    /// A chunk's index is beyond the package.
    #[error("chunk {index} is beyond the {total} this package has")]
    ChunkOutOfRange {
        /// The index that arrived.
        index: u32,
        /// How many chunks the sender declared.
        total: u32,
    },

    /// The sender declared a chunk count of zero.
    #[error("the sender declared no chunks, so there is nothing to receive")]
    NoChunks,

    /// The assembled package does not hash to what was declared.
    #[error("the package hashes to {found} and the sender declared {declared}")]
    DigestMismatch {
        /// What was declared.
        declared: String,
        /// What the bytes hash to.
        found: String,
    },

    /// The sender said the transfer was complete and chunks are missing.
    #[error("the transfer is complete with {missing} chunk(s) missing: {indexes:?}")]
    Incomplete {
        /// How many are missing.
        missing: usize,
        /// Which ones.
        indexes: Vec<u32>,
    },

    /// A receiver's step was performed out of order, or before the step it depends on.
    ///
    /// ★ Why the order is a refusal rather than a convention.
    ///
    /// The design lists the obligations in the order they must happen — the digest before the unpack, the unpack before
    /// the install, the install before deciding whether to enable. A list in a document is a list somebody skips, and the
    /// skip that matters here is silent: unpacking before the digest is verified turns a hostile package into a directory
    /// of files, and installing before the signature is checked writes an unverified component to disk. So each step asks
    /// for the ones before it and this is what it says when one is missing.
    #[error("{missing} cannot be performed before {before}")]
    OutOfOrder {
        /// The step that was attempted.
        missing: &'static str,
        /// The step it depends on.
        before: &'static str,
    },

    /// A step that examines the package refused it.
    #[error("{step} refused the package: {why}")]
    StepRefused {
        /// Which step.
        step: &'static str,
        /// What it said.
        why: String,
    },

    /// There is not enough room where the package would be unpacked.
    ///
    /// ★ The figure comes from [`synra_observe::doctor::free_space`], which reads the mount table. Until round 128 the
    /// probe could only say a directory accepted a write, so a gate here could not have been written — it would have had
    /// to guess.
    #[error("the package needs {needed} bytes and {free} are free")]
    NoRoom {
        /// What the package needs.
        needed: u64,
        /// What the volume has.
        free: u64,
    },
}

/// A round of sync, as the receiving side sees it.
///
/// # What this holds and what it does not
///
/// It holds **which chunk indices have arrived**, not the bytes: the bytes belong to a transfer session on disk, and a
/// second copy of a package in memory is a second thing to bound. What this adds is everything the transfer layer
/// cannot know — which round a chunk belongs to, what the sender declared, and whether the assembled whole is the
/// package that was promised.
#[derive(Debug)]
pub struct SyncSession {
    session: SyncSessionId,
    plugin_id: PluginId,
    source: DeviceId,
    transfer: TransferId,
    declared_version: String,
    declared_digest: String,
    total_chunks: u32,
    have: BTreeSet<u32>,
    /// How many chunks arrived more than once, which is ordinary after a lost acknowledgement and worth reporting.
    duplicates: u32,
}

impl SyncSession {
    /// Opens a round.
    ///
    /// # Errors
    ///
    /// [`SyncError::NoChunks`] when the sender declared none, because a package with no chunks is not a package.
    pub fn open(
        session: SyncSessionId,
        plugin_id: PluginId,
        source: DeviceId,
        transfer: TransferId,
        declared_version: impl Into<String>,
        declared_digest: impl Into<String>,
        total_chunks: u32,
    ) -> Result<Self, SyncError> {
        if total_chunks == 0 {
            return Err(SyncError::NoChunks);
        }
        Ok(Self {
            session,
            plugin_id,
            source,
            transfer,
            declared_version: declared_version.into(),
            declared_digest: declared_digest.into(),
            total_chunks,
            have: BTreeSet::new(),
            duplicates: 0,
        })
    }

    /// The round this is.
    #[must_use]
    pub const fn session(&self) -> &SyncSessionId {
        &self.session
    }

    /// Which plugin.
    #[must_use]
    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// Which device it came from.
    #[must_use]
    pub const fn source(&self) -> DeviceId {
        self.source
    }

    /// The version the sender declared.
    #[must_use]
    pub fn declared_version(&self) -> &str {
        &self.declared_version
    }

    /// The digest the sender declared for the whole package.
    #[must_use]
    pub fn declared_digest(&self) -> &str {
        &self.declared_digest
    }

    /// Accepts a chunk.
    ///
    /// # Returns
    ///
    /// Whether it was new. A duplicate is `Ok(false)`, which is what a resumption *is*: a re-sent chunk after a lost
    /// acknowledgement, and a receiver that refused one would make a retry look like corruption.
    ///
    /// # Errors
    ///
    /// [`SyncError::WrongSession`] when the chunk belongs to another round, and [`SyncError::ChunkOutOfRange`] when its
    /// index is beyond the package.
    pub fn absorb(&mut self, session: &SyncSessionId, index: u32) -> Result<bool, SyncError> {
        if session != &self.session {
            return Err(SyncError::WrongSession {
                theirs: session.to_string(),
                ours: self.session.to_string(),
            });
        }
        if index >= self.total_chunks {
            return Err(SyncError::ChunkOutOfRange {
                index,
                total: self.total_chunks,
            });
        }
        if self.have.insert(index) {
            return Ok(true);
        }
        self.duplicates = self.duplicates.saturating_add(1);
        Ok(false)
    }

    /// Which chunks are missing, in order.
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        (0..self.total_chunks)
            .filter(|index| !self.have.contains(index))
            .collect()
    }

    /// How many chunks have arrived.
    #[must_use]
    pub fn received(&self) -> usize {
        self.have.len()
    }

    /// How many chunks arrived more than once.
    #[must_use]
    pub const fn duplicates(&self) -> u32 {
        self.duplicates
    }

    /// The transfer this round belongs to.
    #[must_use]
    pub const fn transfer(&self) -> TransferId {
        self.transfer
    }

    /// Whether every chunk has arrived.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.have.len() == self.total_chunks as usize
    }

    /// Checks an assembled package against what was declared.
    ///
    /// # Errors
    ///
    /// [`SyncError::Incomplete`] when chunks are missing, and [`SyncError::DigestMismatch`] when the whole does not
    /// hash to what the sender promised. Both are the receiver's own check: a device that trusted the sender's word
    /// about the bytes would be a device where compromising one machine compromises every machine it can reach.
    pub fn conclude(&self, declared: &str, actual: &str) -> Result<(), SyncError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(SyncError::Incomplete {
                missing: missing.len(),
                indexes: missing,
            });
        }
        if declared != actual {
            return Err(SyncError::DigestMismatch {
                declared: declared.to_owned(),
                found: actual.to_owned(),
            });
        }
        Ok(())
    }
}
