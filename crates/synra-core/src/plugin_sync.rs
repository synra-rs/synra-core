//! Sending a plugin to another device: what the far end has, what to do about it, and what the receiver owes itself.
//!
//! # Why this is a decision and not a transfer
//!
//! The bytes move over [`crate::transfer`], which already has sessions, resumption and a digest. What is *not* there is
//! everything that makes this a plugin sync rather than a file copy: comparing two devices' versions, refusing to
//! downgrade, isolating one round of sync from the next, and the receiver's own obligation to re-verify a package that
//! came from a device it trusts.
//!
//! # The two rules that are the whole design
//!
//! **A device never downgrades another's plugin.** The default conflict policy is [`ConflictPolicy::NeverDowngrade`],
//! and the reason is not tidiness: an automatic downgrade can put a device back on a version with a known
//! vulnerability, and "my software was remotely rolled back" is a thing users are right to refuse.
//!
//! **The receiver decides.** Signature, digest, manifest, archive limits and the grant are all checked *again* on the
//! receiving side, by the same [`crate::verify`] pipeline an install from a registry goes through. A device that
//! trusted the sender's word would be a device where compromising one plugin on one machine compromises every machine
//! it can reach — which is the shape of the attack this product exists to make boring.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use synra_protocol::ids::{DeviceId, PluginId, TransferId};

/// Which round of sync a message belongs to.
///
/// # Why a session identifier and not the transfer's
///
/// Because a transfer identifier is chosen by the sender and the same one may be reused, while this is chosen per
/// round and is what stops a *late* chunk from one round being absorbed into the next. Two devices that sync, are
/// interrupted, and sync again would otherwise be two conversations sharing one set of chunk numbers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SyncSessionId(String);

impl SyncSessionId {
    /// A session identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SyncSessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What the other device says it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteState {
    /// Which plugin.
    pub plugin_id: PluginId,
    /// The version it has, or `None` when it has none.
    pub version: Option<String>,
    /// The digest of its artifact, when it has one.
    ///
    /// The comparison that matters: two devices may hold the same *version string* with different bytes — a rebuilt
    /// artifact, a hand-edited bundle — and comparing versions alone would call that "already synced".
    pub digest: Option<String>,
    /// Whether it is running there.
    pub active: bool,
}

impl RemoteState {
    /// A device that does not have the plugin at all.
    #[must_use]
    pub const fn absent(plugin_id: PluginId) -> Self {
        Self { plugin_id, version: None, digest: None, active: false }
    }

    /// Whether it has the plugin in any form.
    #[must_use]
    pub const fn has_it(&self) -> bool {
        self.version.is_some()
    }
}

/// What to do about what the other device has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictPolicy {
    /// Keep both devices' versions as they are.
    ///
    /// **The default.** An automatic downgrade can put a device back on a version with a known vulnerability, and a
    /// user's objection to having their software rolled back remotely is not a preference to be configured away.
    NeverDowngrade,
    /// What the sending device has wins, whatever it is.
    ///
    /// Available because a user *can* mean it — a device being brought in line deliberately — and never the default.
    SourceWins,
    /// Whichever version is newer wins.
    KeepNewest,
    /// Do not reconcile: each device keeps what it has, and a sync does nothing.
    Independent,
    /// Ask the user.
    Ask,
}

impl ConflictPolicy {
    /// A name, for a log line and a setting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverDowngrade => "never-downgrade",
            Self::SourceWins => "source-wins",
            Self::KeepNewest => "keep-newest",
            Self::Independent => "independent",
            Self::Ask => "ask",
        }
    }
}

/// What a sync should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncAction {
    /// Send the package.
    Push {
        /// Why, in a sentence a log line can carry.
        why: String,
    },
    /// Nothing to do.
    Skip {
        /// Why.
        why: String,
    },
    /// The user has to decide.
    Ask {
        /// What they are deciding between.
        ours: String,
        /// The other device's version, when it has one.
        theirs: Option<String>,
    },
    /// Refused, and the sender should not try again unasked.
    Refuse {
        /// Why.
        why: String,
    },
}

impl SyncAction {
    /// Whether this ends the sync with the package sent.
    #[must_use]
    pub const fn is_push(&self) -> bool {
        matches!(self, Self::Push { .. })
    }

    /// A name, for a metric label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Push { .. } => "push",
            Self::Skip { .. } => "skip",
            Self::Ask { .. } => "ask",
            Self::Refuse { .. } => "refuse",
        }
    }
}

/// Compares what this device has with what the other one said.
///
/// # The order the comparisons happen in
///
/// The **digest** first, because it is the answer to "do they already have this artifact" — two devices may hold the
/// same version string with different bytes, and comparing versions alone would call that synced. Then the version,
/// which is what the conflict policies are about.
#[must_use]
pub fn decide(
    ours_version: &str,
    ours_digest: &str,
    theirs: &RemoteState,
    policy: ConflictPolicy,
) -> SyncAction {
    let Some(theirs_version) = theirs.version.as_deref() else {
        return SyncAction::Push { why: "the other device does not have this plugin".to_owned() };
    };

    // ★ Same bytes is the same plugin, whatever the version strings say. A rebuilt artifact with an unchanged version
    // is the case this catches, and a sender that pushed it again would waste a transfer and change nothing.
    if theirs.digest.as_deref() == Some(ours_digest) {
        return SyncAction::Skip { why: "the other device already has these exact bytes".to_owned() };
    }

    match policy {
        ConflictPolicy::Independent => SyncAction::Skip {
            why: "this device is configured to keep its plugins independent".to_owned(),
        },
        ConflictPolicy::SourceWins => {
            SyncAction::Push { why: "this device's version wins by policy".to_owned() }
        }
        ConflictPolicy::Ask => SyncAction::Ask {
            ours: ours_version.to_owned(),
            theirs: Some(theirs_version.to_owned()),
        },
        ConflictPolicy::NeverDowngrade => {
            if compare_versions(ours_version, theirs_version).is_lt() {
                // ★ The rule the default exists for: the other device has something newer, and sending this one would
                // take it backwards.
                SyncAction::Skip {
                    why: format!(
                        "the other device is on {theirs_version} and this device has {ours_version}, which is older"
                    ),
                }
            }
            else {
                SyncAction::Push { why: format!("{ours_version} is not older than {theirs_version}") }
            }
        }
        ConflictPolicy::KeepNewest => {
            if compare_versions(ours_version, theirs_version).is_gt() {
                SyncAction::Push { why: format!("{ours_version} is newer than {theirs_version}") }
            }
            else {
                SyncAction::Skip {
                    why: format!("{theirs_version} is at least as new as {ours_version}"),
                }
            }
        }
    }
}

/// Compares two version strings by their numeric parts.
///
/// The same shape the registry's comparison has, and for the same reason: the one semantic rule that matters for
/// picking between two versions is that a release is newer than its own pre-releases, and plain string ordering gets
/// `1.10.0` and `1.9.0` backwards.
#[must_use]
pub fn compare_versions(first: &str, second: &str) -> core::cmp::Ordering {
    let parts = |version: &str| -> (Vec<u64>, bool) {
        let (core, pre) = version.split_once('-').map_or((version, ""), |(core, pre)| (core, pre));
        let numbers = core.split(['.', '+']).map(|part| part.parse::<u64>().unwrap_or(0)).collect();
        (numbers, !pre.is_empty())
    };
    let (left, left_pre) = parts(first);
    let (right, right_pre) = parts(second);
    match left.cmp(&right) {
        core::cmp::Ordering::Equal => match (left_pre, right_pre) {
            (true, false) => core::cmp::Ordering::Less,
            (false, true) => core::cmp::Ordering::Greater,
            _ => core::cmp::Ordering::Equal,
        },
        other => other,
    }
}

/// What the receiving device is obliged to do, and whether it did.
///
/// # Why this is a value with a state
///
/// Because the list in the design document is a list of things that must **not** be skipped, and a list in a document
/// is a list somebody skips. Making each obligation a step that is either done or not makes "did this device re-verify
/// a package it received" a question with an answer rather than a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ReceiverDuty {
    /// The whole package's digest, before anything is unpacked.
    PackageDigest,
    /// The signature, by the same pipeline an install goes through.
    Signature,
    /// The manifest and the capabilities.
    Manifest,
    /// The archive limits: size, entries, depth, traversal, links.
    ArchiveLimits,
    /// Every chunk arrived, session-level, before "complete" means anything.
    SessionComplete,
    /// Whether to enable it, decided here rather than by the sender.
    LocalActivation,
    /// The grants stay this device's, and a sync does not overwrite them.
    LocalGrants,
}

impl ReceiverDuty {
    /// Every obligation, in the order they are performed.
    pub const ALL: &'static [Self] = &[
        Self::PackageDigest,
        Self::Signature,
        Self::Manifest,
        Self::ArchiveLimits,
        Self::SessionComplete,
        Self::LocalActivation,
        Self::LocalGrants,
    ];

    /// A name, for a report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackageDigest => "package-digest",
            Self::Signature => "signature",
            Self::Manifest => "manifest",
            Self::ArchiveLimits => "archive-limits",
            Self::SessionComplete => "session-complete",
            Self::LocalActivation => "local-activation",
            Self::LocalGrants => "local-grants",
        }
    }
}

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
    pub fn absorb(
        &mut self,
        session: &SyncSessionId,
        index: u32,
    ) -> Result<bool, SyncError> {
        if session != &self.session {
            return Err(SyncError::WrongSession { theirs: session.to_string(), ours: self.session.to_string() });
        }
        if index >= self.total_chunks {
            return Err(SyncError::ChunkOutOfRange { index, total: self.total_chunks });
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
        (0..self.total_chunks).filter(|index| !self.have.contains(index)).collect()
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
            return Err(SyncError::Incomplete { missing: missing.len(), indexes: missing });
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
        !self.installed || ReceiverDuty::ALL.iter().all(|duty| self.performed.contains(duty))
    }

    /// A sentence for the sending device and for a log.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.error, self.installed_version.as_deref()) {
            (Some(error), _) => format!("{} could not be synced: {error}", self.plugin_id),
            (None, Some(version)) => {
                let state = if self.activated { "enabled" } else { "installed" };
                format!("{} {version} is {state} on this device", self.plugin_id)
            }
            (None, None) => format!("{} was not installed", self.plugin_id),
        }
    }
}

/// What a device does about a plugin somebody else has, for a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    /// Which plugin.
    pub plugin_id: PluginId,
    /// Which device.
    pub peer: DeviceId,
    /// What happened.
    pub action: SyncAction,
    /// When, in signed milliseconds since the epoch.
    pub at_ms: i64,
}

impl SyncRecord {
    /// A record of what a sync decided.
    #[must_use]
    pub const fn new(plugin_id: PluginId, peer: DeviceId, action: SyncAction, at_ms: i64) -> Self {
        Self { plugin_id, peer, action, at_ms }
    }

    /// A sentence for a log line.
    #[must_use]
    pub fn describe(&self) -> String {
        let why = match &self.action {
            SyncAction::Push { why } | SyncAction::Skip { why } | SyncAction::Refuse { why } => why.as_str(),
            SyncAction::Ask { ours, theirs } => {
                return format!(
                    "{} on {}: ask, this device has {ours} and the other has {}",
                    self.plugin_id,
                    self.peer,
                    theirs.as_deref().unwrap_or("nothing")
                );
            }
        };
        format!("{} on {}: {} ({why})", self.plugin_id, self.peer, self.action.as_str())
    }
}

/// Every device's last known state for one plugin, so a report can say what is where.
#[derive(Debug, Clone, Default)]
pub struct SyncTable {
    entries: BTreeMap<(PluginId, DeviceId), RemoteState>,
}

impl SyncTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what a device has.
    pub fn record(&mut self, device: DeviceId, state: RemoteState) {
        let _ = self.entries.insert((state.plugin_id.clone(), device), state);
    }

    /// What a device has, if anything is known.
    #[must_use]
    pub fn state_of(&self, plugin_id: &PluginId, device: DeviceId) -> Option<&RemoteState> {
        self.entries.get(&(plugin_id.clone(), device))
    }

    /// Every device's state for one plugin, ordered by device so two reports agree.
    #[must_use]
    pub fn for_plugin(&self, plugin_id: &PluginId) -> Vec<(DeviceId, &RemoteState)> {
        self.entries
            .iter()
            .filter(|((plugin, _), _)| plugin == plugin_id)
            .map(|((_, device), state)| (*device, state))
            .collect()
    }

    /// How many entries are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[path = "plugin_sync_tests.rs"]
mod tests;
