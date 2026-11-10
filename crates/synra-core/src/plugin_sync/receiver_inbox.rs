use super::*;

/// The chunks of a round, kept while they arrive — the receiving half of `16` §5.2 ④–⑦.
///
/// # Why this exists, and what was missing without it
///
/// [`SyncSession`] already accounted for which chunks had arrived, and [`ReceiverCheck`] already knew what to verify once
/// they all had. What neither does is hold the **bytes**: a session knows that chunk 3 is in, and a check knows what to do
/// with a whole package, but between them sat the part that actually receives — and nothing had it. The daemon sends
/// files and does not receive them; its inbound path handles intents. So the receiver was a state machine with no inbox.
///
/// This is that inbox, and it is deliberately the boring version: chunks in memory, assembled on completion. The socket
/// loop and the spill-to-disk of a large package are the daemon's business, and a type that pretended to do them would be
/// the kind of thing this codebase keeps removing — a plausible shape over work nobody did.
///
/// # Why the accounting is not repeated here
///
/// [`SyncSession::absorb`] already answers "is this index new, in range, and in this round", and it already reports the
/// three refusals by name. Re-implementing that here would give two answers to one question, which is how they drift.
#[derive(Debug)]
pub struct SyncInbox {
    session: SyncSession,
    /// The bytes themselves, by index — a map rather than a `Vec`, because chunks arrive out of order and an index is not
    /// a position until every one is in.
    chunks: BTreeMap<u32, Vec<u8>>,
    /// How many chunks were refused for naming another round.
    ///
    /// Counted rather than dropped in silence: a non-zero figure is the only evidence that somebody is sending this
    /// device a round it is not in, and `WrongSession` exists precisely because mixing two rounds corrupts a package in
    /// a way no digest catches until the end.
    refused_chunks: u32,
}

impl SyncInbox {
    /// Opens a round: the sender's declaration, and nothing received yet.
    ///
    /// # Errors
    ///
    /// [`SyncError::NoChunks`] when the sender declared none.
    pub fn begin(
        session: SyncSessionId,
        plugin_id: PluginId,
        source: DeviceId,
        transfer: TransferId,
        declared_version: impl Into<String>,
        declared_digest: impl Into<String>,
        total_chunks: u32,
    ) -> Result<Self, SyncError> {
        Ok(Self {
            session: SyncSession::open(
                session,
                plugin_id,
                source,
                transfer,
                declared_version,
                declared_digest,
                total_chunks,
            )?,
            chunks: BTreeMap::new(),
            refused_chunks: 0,
        })
    }

    /// The round this inbox is for.
    #[must_use]
    pub const fn session(&self) -> &SyncSession {
        &self.session
    }

    /// How many chunks were refused for naming another round.
    #[must_use]
    pub const fn refused_chunks(&self) -> u32 {
        self.refused_chunks
    }

    /// How many chunks are held.
    #[must_use]
    pub fn held(&self) -> usize {
        self.chunks.len()
    }

    /// Takes one chunk.
    ///
    /// The session decides whether it belongs here; this only stores what the session accepted. A chunk that names
    /// another round is counted and refused rather than stored — see [`SyncInbox::refused_chunks`].
    ///
    /// # Errors
    ///
    /// [`SyncError::WrongSession`] for a chunk from another round, [`SyncError::ChunkOutOfRange`] for an index beyond the
    /// declaration, and [`SyncError::Incomplete`] is **not** raised here — it belongs to assembly.
    pub fn absorb(
        &mut self,
        session: &SyncSessionId,
        index: u32,
        bytes: Vec<u8>,
    ) -> Result<(), SyncError> {
        match self.session.absorb(session, index) {
            Ok(_fresh) => {
                // A repeat replaces the bytes rather than adding: the same index twice is the same chunk, and a lost
                // acknowledgement is the ordinary reason it happens. Keeping the first copy and dropping the second would
                // also be defensible; keeping the latest is what "the sender retried" means.
                let _ = self.chunks.insert(index, bytes);
                Ok(())
            }
            Err(error) => {
                if matches!(error, SyncError::WrongSession { .. }) {
                    self.refused_chunks = self.refused_chunks.saturating_add(1);
                }
                Err(error)
            }
        }
    }

    /// The package, once every chunk is in.
    ///
    /// # Errors
    ///
    /// [`SyncError::Incomplete`] naming what is missing. Assembly is refused rather than padded, because a package
    /// assembled from the chunks that happened to arrive is one that would fail its digest for a reason that says nothing
    /// about which chunk was lost.
    pub fn assemble(&self) -> Result<Vec<u8>, SyncError> {
        if !self.session.is_complete() {
            let indexes = self.session.missing();
            return Err(SyncError::Incomplete {
                missing: indexes.len(),
                indexes,
            });
        }
        // Ordered by index, not by arrival: that is the difference between the package the sender hashed and a
        // permutation of it.
        let mut package = Vec::new();
        for chunk in self.chunks.values() {
            package.extend_from_slice(chunk);
        }
        Ok(package)
    }
}
