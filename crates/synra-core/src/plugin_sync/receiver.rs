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

/// The receiving side of the flow in `16` §5.2, as steps that cannot be skipped.
///
/// # Why this exists
///
/// The seven obligations in [`ReceiverDuty`] were a **list**: an enum, an `ALL`, and a test asserting it has seven entries.
/// Nothing performed them in order — the design says so itself, in as many words: *"there is no nine-step flow and no
/// orchestrator."* And [`SyncOutcome::installed`] used to fill `performed` with the whole list, which is what a report
/// looks like when nobody has done the work: true by construction, unverifiable in fact.
///
/// # Why the order is a refusal rather than a convention
///
/// Because each violation is **silent**. Unpacking before the digest is verified turns a hostile package into a directory
/// of files. Installing before the signature is checked writes an unverified component to disk. Enabling before the grants
/// are read overwrites a decision the user made on **this** device.
///
/// So every step requires the ones before it, and a step out of order is a named refusal rather than a success that is one
/// step short.
///
/// The order is the one [`ReceiverDuty`] declares, which the type documents as *"the order they are performed"*.
#[derive(Debug, Default)]
pub struct ReceiverCheck {
    performed: Vec<ReceiverDuty>,
    /// What this device decided about activation. Nobody else's to decide — `16` §5.4 rule 7.
    activated: bool,
}

impl ReceiverCheck {
    /// A check that has performed nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            performed: Vec::new(),
            activated: false,
        }
    }

    /// The duties performed so far, in the order they were performed.
    #[must_use]
    pub fn performed(&self) -> &[ReceiverDuty] {
        &self.performed
    }

    /// Whether the device chose to enable the plugin once it was installed.
    ///
    /// Local, and that is the point: the sender says what it has, not what this device should run.
    #[must_use]
    pub const fn activated(&self) -> bool {
        self.activated
    }

    /// Requires that `before` has been performed. Records nothing.
    ///
    /// # Errors
    ///
    /// [`SyncError::OutOfOrder`] naming both steps.
    fn require(&self, duty: ReceiverDuty, before: ReceiverDuty) -> Result<(), SyncError> {
        if self.performed.contains(&before) {
            return Ok(());
        }
        Err(SyncError::OutOfOrder {
            missing: duty.as_str(),
            before: before.as_str(),
        })
    }

    /// Requires the predecessor **and** records the step.
    ///
    /// Both halves matter: a step that fails its predecessor leaves no trace, so `performed` never claims work that a
    /// refusal prevented.
    ///
    /// # Errors
    ///
    /// [`SyncError::OutOfOrder`] when the predecessor has not been performed.
    fn record(&mut self, duty: ReceiverDuty, before: ReceiverDuty) -> Result<(), SyncError> {
        self.require(duty, before)?;
        self.performed.push(duty);
        Ok(())
    }

    /// ⑧ first: the whole package\'s digest, before anything is unpacked.
    ///
    /// # Errors
    ///
    /// [`SyncError::Incomplete`] when chunks are missing — a digest of an incomplete package is a digest of the wrong
    /// bytes — and [`SyncError::DigestMismatch`] when the bytes do not hash to what the sender declared.
    pub fn verify_digest(&mut self, session: &SyncSession, actual: &str) -> Result<(), SyncError> {
        if !session.is_complete() {
            return Err(SyncError::Incomplete {
                missing: session.missing().len(),
                indexes: session.missing(),
            });
        }
        session.conclude(session.declared_digest(), actual)?;
        self.performed.push(ReceiverDuty::PackageDigest);
        Ok(())
    }

    /// The signature, by the same pipeline an install goes through.
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] carrying what the verifier said.
    pub fn verify_signature(
        &mut self,
        accepted: bool,
        why: impl Into<String>,
    ) -> Result<(), SyncError> {
        self.require(ReceiverDuty::Signature, ReceiverDuty::PackageDigest)?;
        if !accepted {
            return Err(SyncError::StepRefused {
                step: ReceiverDuty::Signature.as_str(),
                why: why.into(),
            });
        }
        self.performed.push(ReceiverDuty::Signature);
        Ok(())
    }

    /// The manifest and the capabilities.
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] carrying what the manifest check said.
    pub fn check_manifest(
        &mut self,
        accepted: bool,
        why: impl Into<String>,
    ) -> Result<(), SyncError> {
        self.require(ReceiverDuty::Manifest, ReceiverDuty::Signature)?;
        if !accepted {
            return Err(SyncError::StepRefused {
                step: ReceiverDuty::Manifest.as_str(),
                why: why.into(),
            });
        }
        self.performed.push(ReceiverDuty::Manifest);
        Ok(())
    }

    /// The archive limits: size, entries, depth, traversal, links.
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] carrying the limit that was exceeded.
    pub fn check_archive(
        &mut self,
        accepted: bool,
        why: impl Into<String>,
    ) -> Result<(), SyncError> {
        self.require(ReceiverDuty::ArchiveLimits, ReceiverDuty::Manifest)?;
        if !accepted {
            return Err(SyncError::StepRefused {
                step: ReceiverDuty::ArchiveLimits.as_str(),
                why: why.into(),
            });
        }
        self.performed.push(ReceiverDuty::ArchiveLimits);
        Ok(())
    }

    /// Whether there is room where the package would be unpacked.
    ///
    /// # Where the figure comes from
    ///
    /// [`synra_observe::doctor::free_space`], which reads the mount table in safe Rust. Until round 128 the doctor could
    /// only say a directory accepted a write, so a gate here could not have been written — it would have had to guess.
    ///
    /// ★ And it compares against **what the package needs**, not against [`synra_observe::doctor::LOW_DISK_BYTES`]. The
    /// low-disk threshold is a warning about the machine; refusing a 2 MiB plugin because the disk is under 500 MiB would
    /// be this gate inventing a policy that belongs to the settings screen.
    ///
    /// # Errors
    ///
    /// [`SyncError::NoRoom`] naming both figures, and [`SyncError::StepRefused`] when the host cannot report free space —
    /// because "I do not know" is not "there is room".
    pub fn check_room(&mut self, root: &std::path::Path, needed: u64) -> Result<(), SyncError> {
        self.require(ReceiverDuty::ArchiveLimits, ReceiverDuty::Manifest)?;
        let Some(free) = synra_observe::doctor::free_space(root) else {
            return Err(SyncError::StepRefused {
                step: "room",
                why: "this host did not report the free space, so there is no way to know the package fits".to_owned(),
            });
        };
        if free < needed {
            return Err(SyncError::NoRoom { needed, free });
        }
        Ok(())
    }

    /// Every chunk arrived, session-level.
    ///
    /// # Errors
    ///
    /// [`SyncError::Incomplete`] when the session is not complete.
    pub fn check_session_complete(&mut self, session: &SyncSession) -> Result<(), SyncError> {
        self.require(ReceiverDuty::SessionComplete, ReceiverDuty::ArchiveLimits)?;
        if !session.is_complete() {
            return Err(SyncError::Incomplete {
                missing: session.missing().len(),
                indexes: session.missing(),
            });
        }
        self.performed.push(ReceiverDuty::SessionComplete);
        Ok(())
    }

    /// Whether to enable it, decided here rather than by the sender.
    ///
    /// # Errors
    ///
    /// [`SyncError::OutOfOrder`] when the session has not been confirmed complete.
    pub fn decide_activation(&mut self, enabled: bool) -> Result<(), SyncError> {
        self.record(ReceiverDuty::LocalActivation, ReceiverDuty::SessionComplete)?;
        self.activated = enabled;
        Ok(())
    }

    /// The grants stay this device\'s, and a sync does not overwrite them.
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] when the grants were **not** kept, which is the one outcome this step exists to prevent.
    pub fn keep_local_grants(&mut self, kept: bool) -> Result<(), SyncError> {
        self.require(ReceiverDuty::LocalGrants, ReceiverDuty::LocalActivation)?;
        if !kept {
            return Err(SyncError::StepRefused {
                step: ReceiverDuty::LocalGrants.as_str(),
                why: "the sync would have replaced this device\'s grants, which are local"
                    .to_owned(),
            });
        }
        self.performed.push(ReceiverDuty::LocalGrants);
        Ok(())
    }

    /// The outcome, naming the duties this check **actually performed**.
    ///
    /// # Why the list is not [`ReceiverDuty::ALL`]
    ///
    /// Because a check that skipped a step must not produce a report saying it did not. This is the call
    /// [`SyncOutcome::installed`] was waiting for: the constructor takes the list, and this is the only thing in the crate
    /// that can honestly produce one.
    #[must_use]
    pub fn finish(
        self,
        plugin_id: PluginId,
        session: SyncSessionId,
        version: impl Into<String>,
    ) -> SyncOutcome {
        SyncOutcome::installed(plugin_id, session, version, self.activated, self.performed)
    }
}

/// One round of synchronisation, as the sender sees it.
///
/// ★ **Why the three travel as one value rather than as three arguments.**
///
/// They belong together by construction: a round is about **one plugin at one version**, and a round whose declaration
/// disagreed with the package it carried would be a message nobody could act on. They also would not fit — `send_bundle`
/// was already at clippy's argument limit, and the honest answer to that is to name the thing rather than to allow the
/// lint.
///
/// ★ **Why the sender chooses the session and the receiver does not.**
///
/// A round is started by one side, and that side is the only one that can name it: two devices pushing at the same
/// moment would each invent an identifier the other has never heard of, and neither could match a result to a round.
/// The receiver's job is to repeat it back — which is what `TransferRequest::sync_session_id` carries it for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRound {
    /// Which plugin this round is about.
    pub plugin_id: PluginId,
    /// Which version is being sent.
    pub version: String,
    /// Which round it is.
    ///
    /// ★ The protocol's identifier rather than this module's [`SyncSessionId`], because this is the value that travels:
    /// `TransferRequest::sync_session_id` is an `Option<SessionId>`, and a round the other side cannot name is a round
    /// it cannot answer. The two types name the same thing; only one of them fits in a packet.
    pub session: synra_protocol::ids::SessionId,
}
