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
    ///
    /// ★ **A digest counts, and that is a correction rather than a convenience.**
    ///
    /// This read `self.version.is_some()`, and it was wrong about the shape the **receiving** side writes: a row whose
    /// digest the transferred file proved and whose version is empty, because a `Decision` does not carry one (round
    /// 150). Such a peer holds the artifact — the digest is precisely what says which bytes.
    ///
    /// The old answer read that as "it does not have the plugin", which is the one thing a sync decision must not get
    /// wrong: it would push the same package again on every round, forever.
    ///
    /// ★ The counter-example came from a test rather than from reasoning: `from_rows` loaded such a row and
    /// `assert!(receiver.has_it())` failed (round 161). That assertion was withdrawn then, and it is back now.
    #[must_use]
    pub const fn has_it(&self) -> bool {
        self.version.is_some() || self.digest.is_some()
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
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
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

/// 一条同步记录的标识。
///
/// 与会话标识分开：一轮会话可以产生不止一条记录（发起端与接收端各记自己的），
/// 而一条记录要能被单独引用、排序和去重。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncId(String);

impl SyncId {
    /// 一个标识，名字由调用方给。
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// 标识本身。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 这一轮是谁推给谁。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDirection {
    /// 本机推给对端。
    Push,
    /// 对端推给本机。
    Pull,
}

/// 一轮同步的结局，三态。
///
/// ★ **而它不能叫 `SyncOutcome`。** 那个名字在本模块里已经是一个**不同**的东西：
/// 接收端做过哪些义务的清单（[`SyncOutcome`]）。文档 §5.5 的 `SyncOutcome` 是这三态，
/// 代码的 [`SyncOutcome`] 是记账 —— 同名不同物。给新的这个起一个准确的名字，
/// 比重命名一个已经有生产调用者的类型代价小。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SyncVerdict {
    /// 装上了。
    Succeeded,
    /// 双方已经一致，所以没有传输 —— 与失败不同，它不需要任何人做什么。
    Skipped {
        /// 为什么跳过。
        reason: String,
    },
    /// 被拒绝了。
    Failed {
        /// 原因。
        error: String,
    },
}

/// 一次同步留下了什么，够 §5.5 的可观测性和界面用。
///
/// 这条记录**就是**那一步的产物：以前它只有四个字段（插件、对端、决定、时间），
/// 所以一次同步结束之后没有任何地方说得出来它成没成、传了多少。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    /// 这条记录自己的标识。
    pub id: SyncId,
    /// 哪个插件。
    pub plugin_id: PluginId,
    /// 对端当时持有什么版本，或本机推过去的版本。
    pub version: Option<String>,
    /// 谁推给谁。
    pub direction: SyncDirection,
    /// 哪台设备。
    pub peer: DeviceId,
    /// 当时的**决定**（推送 / 跳过 / 询问）。
    ///
    /// 与 `verdict` 不同，也不是它的前身：决定是第 ③ 步的产物，结局是第 ⑧ 步的产物，
    /// 而一次「决定推送、结果失败」的记录需要对这两件事都说得出来。
    pub action: SyncAction,
    /// 什么时候开始的，有符号毫秒。
    ///
    /// 有符号毫秒而不是 `SystemTime`：仓库里每一个时间戳都是这个形状
    /// （`Runtime` 的 `started_at_ms`、每一张表的时间列），而一个 `SyncRecord` 要与它们比较、
    /// 要能存进 SQLite。文档写的 `SystemTime` 是意图，这个形状是实现它的方式。
    pub started_at_ms: i64,
    /// 什么时候结束的，还没结束时为 `None`。
    pub finished_at_ms: Option<i64>,
    /// 结局，还没结束时为 `None`。
    ///
    /// 与 `finished_at_ms` 同时为空或有值：一条已经结束却没有结局的记录，
    /// 和一条有结局却没有结束时间的记录，都是自相矛盾的。
    pub verdict: Option<SyncVerdict>,
    /// 传了多少字节。
    pub bytes_transferred: u64,
    /// 这一轮属于哪条追踪，还没认出是哪一轮时为 `None`。
    pub trace_id: Option<synra_protocol::ids::TraceId>,
}

impl SyncRecord {
    /// A record of what a sync decided.
    #[must_use]
    pub const fn new(
        plugin_id: PluginId,
        peer: DeviceId,
        action: SyncAction,
        started_at_ms: i64,
    ) -> Self {
        // 一条刚刚开始的记录：没有结束时间、没有结局、没有字节。
        Self {
            id: SyncId(String::new()),
            plugin_id,
            version: None,
            direction: SyncDirection::Push,
            peer,
            action,
            started_at_ms,
            finished_at_ms: None,
            verdict: None,
            bytes_transferred: 0,
            trace_id: None,
        }
    }

    /// 把这一轮写成库里的一行（迁移 v10 的 `sync_log`）。
    ///
    /// ★ 形状照 `intents`（迁移 v9）的先例：**整份文档 + 查询用的投影列**。
    /// `document` 是整份记录的序列化；旁边的列是历史页面真正要问的两个问题
    /// （最新在前、按插件过滤）。它们必须与 `document` 里的同一件事一致，
    /// 而这里保证这一点的方式是：两者都从**同一个** `self` 取。
    ///
    /// # Errors
    ///
    /// 序列化失败。对一个全是普通数据的结构体这不会发生，但返回 `Result` 好过 `panic` ——
    /// 而且工作区禁止 `unwrap`，所以「不会发生」也必须有人接着。
    pub fn to_row(&self) -> Result<synra_store::records::SyncLogRow, serde_json::Error> {
        Ok(synra_store::records::SyncLogRow {
            sync_id: self.id.as_str().to_owned(),
            plugin_id: self.plugin_id.to_string(),
            peer_device: self.peer.to_string(),
            started_at_ms: self.started_at_ms,
            finished_at_ms: self.finished_at_ms,
            document: serde_json::to_string(self)?,
        })
    }

    /// 从库里的一行读回这一轮。
    ///
    /// ★ **`document` 是权威。** 投影列是给查询用的索引；与文档不一致的列只可能来自有人手工改过库，
    /// 而那时相信哪一半都不对 —— 这里选择相信完整的那一半，并把不一致留给一个单独的检查
    /// （而不是在这里悄悄让列赢）。
    ///
    /// # Errors
    ///
    /// 文档不是这一轮的序列化。
    pub fn from_row(row: &synra_store::records::SyncLogRow) -> Result<Self, serde_json::Error> {
        serde_json::from_str(&row.document)
    }

    /// 给记录一个身份、一个方向、一个版本和一条追踪。
    ///
    /// 分开而不是塞进 `new`：`new` 的调用点只关心「决定了什么」，
    /// 而身份与追踪是这一轮被真正记下来时才有的东西。
    #[must_use]
    pub fn identified(
        mut self,
        id: SyncId,
        direction: SyncDirection,
        version: Option<String>,
        trace_id: synra_protocol::ids::TraceId,
    ) -> Self {
        self.id = id;
        self.direction = direction;
        self.version = version;
        self.trace_id = Some(trace_id);
        self
    }

    /// 收尾：结局、字节数与结束时间。
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] 当这条记录已经收过尾 —— 收两次的结局覆盖第一次，
    /// 而那正是「最后的说法赢」这种没人看得出来的错。
    pub fn finished(
        mut self,
        verdict: SyncVerdict,
        bytes_transferred: u64,
        at_ms: i64,
    ) -> Result<Self, SyncError> {
        if self.verdict.is_some() {
            return Err(SyncError::StepRefused {
                step: "sync-record",
                why: "this record already has a verdict, and a second one would silently replace the first".to_owned(),
            });
        }
        self.verdict = Some(verdict);
        self.bytes_transferred = bytes_transferred;
        self.finished_at_ms = Some(at_ms);
        Ok(self)
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

    /// ⑨ 的第一半：发起端把一轮同步的结局写进它对本机的认识。
    ///
    /// ★ **为什么这条是 `record` 唯一的<ins>生产</ins>调用者。**
    ///
    /// 这张表能存、能查、能按插件列出，但从写下来那天起没有任何东西把一次同步的**结果**写进去，
    /// 所以 §5.2 第 ⑨ 步（「A 更新同步状态，UI 显示」）没有实现 —— 表和回复都在，缺的是把两半接起来的这一行。
    ///
    /// ★ **而失败时不改这张表，这是语义而不是省事。**
    ///
    /// 一次失败的同步没有改变对端持有什么：它仍然有原来那个版本。写成「什么也没有」会让下一次推送判断成
    /// 「它需要」，于是重复传输；写成「新版本」更糟 —— 表会声称对端有一个它从未收到的包。
    /// 失败属于**历史**（§5.5 的 `SyncRecord`），不属于「对端现在有什么」。
    ///
    /// ★ 而摘要从**参数**来，不从回复来：回复里没有摘要，也不需要 —— 发起端推的就是那个包，摘要是它自己算的。
    /// 让对端回报摘要会多一个可以撒谎的地方。
    pub fn apply_result(
        &mut self,
        device: DeviceId,
        plugin_id: &PluginId,
        result: &crate::messaging::SyncResult,
        pushed_digest: &str,
    ) {
        if !result.ok {
            return;
        }
        // 说成功却没有版本，是回复自相矛盾。不更新好过记一个半真半假的状态。
        let Some(version) = result.installed_version.clone() else {
            return;
        };
        self.record(
            device,
            RemoteState {
                plugin_id: plugin_id.clone(),
                version: Some(version),
                digest: Some(pushed_digest.to_owned()),
                active: result.activated,
            },
        );
    }

    /// Loads this table from rows read out of a database.
    ///
    /// ★ **Why this exists.**
    ///
    /// `SyncTable` is the in-memory answer to "what does each device hold"; `sync_records` is the durable one. They are
    /// not duplicates — a kernel without SQLite can use this one — but nothing could get from one to the other, so a
    /// host that read the rows had nowhere to put what it read.
    ///
    /// ★ **One-way on purpose.** The database is the record, and a table that could write back would be a second author
    /// of it — the arrangement this codebase keeps replacing with "one place decides, the rest read".
    ///
    /// ★ **An empty version or digest becomes `None` rather than `Some("")`.** The receiving side writes a row with the
    /// digest the *file* proved and leaves the version empty, because a `Decision` does not carry one. `Some("")` would
    /// read as the claim "the peer holds version ''" rather than as the silence it is — and `has_it` is exactly the
    /// question that would then be answered wrongly.
    ///
    /// ★ **A row this build cannot parse is skipped rather than refused.** The identifier came from a device that may
    /// run another build, and a table that refused to load at all would take the rest of the history down with it.
    #[must_use]
    pub fn from_rows(rows: &[synra_store::records::SyncRow]) -> Self {
        let mut table = Self::new();
        for row in rows {
            let (Ok(plugin_id), Ok(device)) = (
                PluginId::try_from(row.plugin_id.clone()),
                row.peer_device.parse::<DeviceId>(),
            ) else {
                continue;
            };
            table.record(
                device,
                RemoteState {
                    plugin_id,
                    version: Some(row.version.clone()).filter(|version| !version.is_empty()),
                    digest: Some(row.digest.clone()).filter(|digest| !digest.is_empty()),
                    // A row says the peer holds these bytes. Whether it is *running* them is not something this table
                    // was ever told, and guessing would be the kind of claim this codebase keeps removing.
                    active: false,
                },
            );
        }
        table
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
    pub fn absorb(&mut self, session: &SyncSessionId, index: u32, bytes: Vec<u8>) -> Result<(), SyncError> {
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
            return Err(SyncError::Incomplete { missing: indexes.len(), indexes });
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
        Self { performed: Vec::new(), activated: false }
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
        Err(SyncError::OutOfOrder { missing: duty.as_str(), before: before.as_str() })
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
            return Err(SyncError::Incomplete { missing: session.missing().len(), indexes: session.missing() });
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
    pub fn verify_signature(&mut self, accepted: bool, why: impl Into<String>) -> Result<(), SyncError> {
        self.require(ReceiverDuty::Signature, ReceiverDuty::PackageDigest)?;
        if !accepted {
            return Err(SyncError::StepRefused { step: ReceiverDuty::Signature.as_str(), why: why.into() });
        }
        self.performed.push(ReceiverDuty::Signature);
        Ok(())
    }

    /// The manifest and the capabilities.
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] carrying what the manifest check said.
    pub fn check_manifest(&mut self, accepted: bool, why: impl Into<String>) -> Result<(), SyncError> {
        self.require(ReceiverDuty::Manifest, ReceiverDuty::Signature)?;
        if !accepted {
            return Err(SyncError::StepRefused { step: ReceiverDuty::Manifest.as_str(), why: why.into() });
        }
        self.performed.push(ReceiverDuty::Manifest);
        Ok(())
    }

    /// The archive limits: size, entries, depth, traversal, links.
    ///
    /// # Errors
    ///
    /// [`SyncError::StepRefused`] carrying the limit that was exceeded.
    pub fn check_archive(&mut self, accepted: bool, why: impl Into<String>) -> Result<(), SyncError> {
        self.require(ReceiverDuty::ArchiveLimits, ReceiverDuty::Manifest)?;
        if !accepted {
            return Err(SyncError::StepRefused { step: ReceiverDuty::ArchiveLimits.as_str(), why: why.into() });
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
            return Err(SyncError::Incomplete { missing: session.missing().len(), indexes: session.missing() });
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
                why: "the sync would have replaced this device\'s grants, which are local".to_owned(),
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
    pub fn finish(self, plugin_id: PluginId, session: SyncSessionId, version: impl Into<String>) -> SyncOutcome {
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
