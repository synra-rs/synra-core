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

/// What the receiving device did about a package, once it had it.
///
/// # Why every obligation is recorded rather than assumed
///
/// Because the sender is told the result, and "ok" means this device checked the seven things it owes itself. A report
/// that omitted them would make "the sync succeeded" a claim about the transfer rather than about the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Which plugin.
    pub plugin_id: PluginId,
    /// Which round.
    pub session: SyncSessionId,
    /// Which duties were performed.
    pub performed: Vec<ReceiverDuty>,
    /// Whether the package was installed.
    pub installed: bool,
    /// The version that is now installed, when one is.
    pub installed_version: Option<String>,
    /// Whether it was enabled, by **this** device's policy.
    pub activated: bool,
    /// What went wrong, when something did.
    pub error: Option<String>,
}

impl SyncOutcome {
    /// A successful outcome, naming the duties this device actually performed.
    ///
    /// ★ **Why the caller supplies the list rather than this filling in [`ReceiverDuty::ALL`].**
    ///
    /// It used to fill it in. So an outcome built here said every obligation had been carried out — a claim made by a
    /// constructor, about work it had no way to observe. The only reason that was harmless is that nothing in production
    /// called it: the sync orchestrator does not exist yet. The day one appeared it would have inherited a report that was
    /// true by construction and false in fact, which is the shape this file exists to avoid — the design's own comment
    /// says a list in a document is "a list somebody skips", and a list a constructor fills in is skipped by the compiler.
    ///
    /// Now the caller names what it did. [`SyncOutcome::is_fully_checked`] still asks whether the list is complete, and it
    /// can now answer "no" for an outcome that was assembled rather than performed.
    #[must_use]
    pub fn installed(
        plugin_id: PluginId,
        session: SyncSessionId,
        version: impl Into<String>,
        activated: bool,
        performed: Vec<ReceiverDuty>,
    ) -> Self {
        Self {
            plugin_id,
            session,
            performed,
            installed: true,
            installed_version: Some(version.into()),
            activated,
            error: None,
        }
    }

    /// A refusal, naming what stopped it.
    #[must_use]
    pub fn refused(plugin_id: PluginId, session: SyncSessionId, error: impl Into<String>) -> Self {
        Self {
            plugin_id,
            session,
            performed: Vec::new(),
            installed: false,
            installed_version: None,
            activated: false,
            error: Some(error.into()),
        }
    }

    /// Whether the device did everything it owed itself before installing.
    ///
    /// A successful outcome without every duty is a bug rather than a policy, which is why this is asked rather than
    /// assumed — see the test that drives it.
    #[must_use]
    pub fn is_fully_checked(&self) -> bool {
        !self.installed
            || ReceiverDuty::ALL
                .iter()
                .all(|duty| self.performed.contains(duty))
    }

    /// A sentence for the sending device and for a log.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.error, self.installed_version.as_deref()) {
            (Some(error), _) => format!("{} could not be synced: {error}", self.plugin_id),
            (None, Some(version)) => {
                let state = if self.activated {
                    "enabled"
                } else {
                    "installed"
                };
                format!("{} {version} is {state} on this device", self.plugin_id)
            }
            (None, None) => format!("{} was not installed", self.plugin_id),
        }
    }
}

/// Records a bundle that just arrived: what happened, what the peer holds, and the installed row.
///
/// # Why this lives in the kernel rather than in a host
///
/// Because both hosts receive bundles, and the three writes are **one decision**: a history row, a row saying what the
/// peer holds, and a plugin row saying it arrived. Two implementations would let the daemon say "installed" and the
/// window say nothing, which is the same failure as two discovery tables with two data directories — the side that
/// answered is not the side the interface reads.
///
/// # What it does not do
///
/// It does not verify or install the bytes. The transfer proved the digest; the package format — a manifest and a
/// signature over a directory — does not exist yet, and the file stays in the inbox. This writes the row the design's
/// "installed" state is made of, and the returned outcome says **exactly that**: installed, enabled, and **no receiver
/// check performed**. A caller that claimed the seven checks would make the sender's history describe work nobody did.
///
/// # Returns
///
/// `None` for an attachment — a screenshot is not a round of synchronisation, and a history full of them would answer
/// "what has been synced" with rows that were files. Also `None` when the record itself cannot be built, which needs a
/// verdict that is already set and cannot happen from here.
#[must_use]
pub fn record_received(
    db: &synra_store::SynraDb,
    transfer: &crate::listener::FinishedTransfer,
) -> Option<SyncOutcome> {
    let plugin_id = transfer.bundle.clone()?;
    let now = synra_store::sqlite::now_ms();
    let version = transfer.version.clone().unwrap_or_default();

    let record = SyncRecord::new(
        plugin_id.clone(),
        transfer.peer,
        SyncAction::Push {
            why: "the peer sent a bundle".to_owned(),
        },
        now,
    )
    .identified(
        // The path is what makes this row distinct: two bundles for one plugin are two syncs, and the receiver's chosen
        // file name carries both the plugin and the transfer.
        SyncId::new(format!("recv-{}", transfer.path.display())),
        // Received, so the peer pushed: `Pull` is this device's side of it.
        SyncDirection::Pull,
        // ★ The version travels with the transfer (round 163), so the record can say which version arrived rather than
        // leaving it absent. It is the sender's declaration, and the digest beside it is what the file proved.
        transfer.version.clone(),
        TraceId::new(),
    )
    .finished(SyncVerdict::Succeeded, transfer.byte_length, now)
    .ok()?;

    if let Ok(row) = record.to_row() {
        // A history that cannot be written is not a reason to fail a connection that already succeeded.
        let _ = db.record_sync_log(&row);
    }

    // What the peer holds now: `(plugin_id, peer_device)` is the key to that question, and the digest is the half the
    // file proved.
    let _ = db.record_sync(
        plugin_id.as_str(),
        &transfer.peer.to_string(),
        transfer.version.as_deref().unwrap_or_default(),
        &transfer.digest,
        now,
    );

    // ★ Installed, and **not trusted**. `trusted` answers "has the user confirmed what it may do", and a file that just
    // arrived has been confirmed by nobody. `enabled` answers a different question — whether it may run at all — and the
    // store keeps them as two columns for exactly this case: it may run, and nobody has said what it may do yet.
    let _ = db.insert_plugin(plugin_id.as_str(), true, false, "unknown", now, now);

    Some(SyncOutcome::installed(
        plugin_id,
        SyncSessionId::new(
            transfer
                .sync_session_id
                .map_or_else(String::new, |session| session.to_string()),
        ),
        version,
        // ★ `true`, because the row above is `enabled = true`. This used to be whatever `ReceiverCheck` had decided,
        // and that was `false`: `decide_activation` requires `SessionComplete`, which the transfer path never performs,
        // so the outcome contradicted the row it had just written. The list of performed checks stays empty — that part
        // was honest — and `is_fully_checked` therefore answers "no".
        true,
        Vec::new(),
    ))
}
