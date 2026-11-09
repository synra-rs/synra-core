use super::*;

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
    /// Reads one entry of a peer's answer.
    ///
    /// # Why this is a mapping and not a `From`
    ///
    /// Because the two types are allowed to disagree — that is the point of having both. [`PluginSummary`] is what goes on the
    /// wire and must not depend on the kernel; this is the kernel's opinion of it. A `From` would read as "these are the same
    /// thing in two spellings", and the first field that means something slightly different on each side would make that a lie.
    #[must_use]
    pub fn from_summary(summary: &PluginSummary) -> Self {
        Self {
            plugin_id: summary.plugin_id.clone(),
            version: summary.version.clone(),
            digest: summary.digest.clone(),
            active: summary.active,
        }
    }

    /// A device that does not have the plugin at all.
    #[must_use]
    pub const fn absent(plugin_id: PluginId) -> Self {
        Self {
            plugin_id,
            version: None,
            digest: None,
            active: false,
        }
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

/// What this device would answer a peer that asked what plugins it has.
///
/// # Why this reads two tables
///
/// Because the answer is a join the store does not offer: `plugins` says a plugin is installed and whether it may run,
/// and `plugin_versions` says which version is the one in effect. A row in the first with no active row in the second has
/// no artifact to describe, so it is **left out** — the list is what this device could send, not a directory of names.
///
/// # The `active` field is the enabled flag, and that is a documented approximation
///
/// [`PluginSummary::active`] is spelled "whether it is running there" on the wire. This store knows whether a plugin is
/// **allowed** to run, not whether a host has it running at this moment, and inventing the latter would be a claim this
/// device cannot support. The field is advisory: [`decide`] ignores it, and a peer comparing artifacts reads the version
/// and the digest.
///
/// # Errors
///
/// [`synra_store::DbError`] when either table cannot be read. A database this device cannot read is not an empty list: a
/// peer that was told "nothing" would plan to send every plugin, and the next attempt would find out otherwise.
pub fn local_list(db: &synra_store::SynraDb) -> Result<PluginList, synra_store::DbError> {
    let mut plugins = Vec::new();
    for row in db.plugins()? {
        let Some((version, digest)) = db.active_plugin_version(&row.plugin_id)? else {
            continue;
        };
        // ★ An identifier this build cannot parse is skipped rather than made fatal. The same choice `from_rows` makes for
        // a row from another build: one unreadable row must not take the rest of the answer — and the rest of the answer is
        // what a peer needs to decide about every other plugin.
        let Ok(plugin_id) = PluginId::parse(&row.plugin_id) else {
            continue;
        };
        // The empty digest is the store's word for "none", so it does not travel as a claim that the device holds the
        // empty artifact. The receiving side writes the same shape when it knows the bytes but not the version.
        plugins.push(PluginSummary {
            plugin_id,
            version: Some(version),
            digest: (!digest.is_empty()).then_some(digest),
            active: row.enabled,
        });
    }
    Ok(PluginList { plugins })
}

/// Why this device could not answer "what plugins do you have".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ListAnswerError {
    /// The store could not be read.
    #[error(transparent)]
    Store(#[from] synra_store::DbError),

    /// The answer could not be built as an envelope — a list too large for one frame is the case that matters, and it is
    /// refused rather than truncated, because a truncated list reads as "this device has fewer plugins".
    #[error(transparent)]
    Message(#[from] crate::messaging::MessageError),
}

/// Answers a peer's question with this device's list.
///
/// # Why this is a function rather than four lines in the connection loop
///
/// Because the connection loop never returns — it is `serve`'s per-connection thread — so a test cannot reach into it.
/// A request in, an envelope out is the whole obligation, and as a function it is testable without a socket.
///
/// # Errors
///
/// [`ListAnswerError`] when the store cannot be read or the envelope cannot be built.
pub fn answer_plugin_list(
    db: &synra_store::SynraDb,
    request: &synra_protocol::envelope::Envelope,
    from: DeviceId,
    now_ms: i64,
) -> Result<synra_protocol::envelope::Envelope, ListAnswerError> {
    let list = local_list(db)?;
    Ok(crate::messaging::plugin_list_response(
        request, from, &list, now_ms,
    )?)
}

/// Asks a connected peer what plugins it has, and waits for the answer.
///
/// # Why the deadline is an argument rather than a constant here
///
/// Because how long an answer may take is the caller's judgement about its own network and its own command: a plan a
/// person is waiting on and a background refresh do not share one figure. The deadline is checked between reads, so a
/// peer that says nothing produces an error instead of a thread that never comes back.
///
/// # What is skipped rather than refused
///
/// Any other traffic on the link. The answer is the only thing this side is waiting for, and a peer that says something
/// else first — an acknowledgement, a message for another feature — has not broken anything. A block on a link where this
/// side is not receiving is skipped for the same reason: it is not the answer, and the caller's deadline still bounds the
/// wait.
///
/// # Errors
///
/// [`SessionError::Link`] for a failed send, a closed link, or the deadline passing; [`SessionError::Payload`] for an
/// answer that is not a plugin list.
pub fn ask_plugin_list(
    link: &mut crate::link::PeerLink,
    ours: DeviceId,
    peer: DeviceId,
    trace_id: TraceId,
    now_ms: i64,
    deadline: std::time::Instant,
) -> Result<PluginList, crate::SessionError> {
    let request =
        crate::messaging::plugin_list_request(ours, peer, trace_id, now_ms).map_err(|error| {
            crate::SessionError::Payload {
                message: "plugin list request",
                why: error.to_string(),
            }
        })?;
    link.send(&request)?;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(crate::SessionError::Link(crate::link::LinkError::TimedOut));
        }
        match link.receive_inbound() {
            Ok(crate::link::Inbound::Envelope(envelope))
                if envelope.event.as_str()
                    == synra_protocol::event::events::PLUGIN_LIST_RESPONSE =>
            {
                let payload =
                    envelope
                        .payload_str()
                        .ok_or_else(|| crate::SessionError::Payload {
                            message: "plugin list",
                            why: "the answer carried no payload".to_owned(),
                        })?;
                return serde_json::from_str(payload).map_err(|error| {
                    crate::SessionError::Payload {
                        message: "plugin list",
                        why: error.to_string(),
                    }
                });
            }
            Ok(_) => continue,
            Err(crate::link::LinkError::TimedOut) => {
                if std::time::Instant::now() >= deadline {
                    return Err(crate::SessionError::Link(crate::link::LinkError::TimedOut));
                }
                continue;
            }
            Err(error) => return Err(crate::SessionError::Link(error)),
        }
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
        return SyncAction::Push {
            why: "the other device does not have this plugin".to_owned(),
        };
    };

    // ★ Same bytes is the same plugin, whatever the version strings say. A rebuilt artifact with an unchanged version
    // is the case this catches, and a sender that pushed it again would waste a transfer and change nothing.
    if theirs.digest.as_deref() == Some(ours_digest) {
        return SyncAction::Skip {
            why: "the other device already has these exact bytes".to_owned(),
        };
    }

    match policy {
        ConflictPolicy::Independent => SyncAction::Skip {
            why: "this device is configured to keep its plugins independent".to_owned(),
        },
        ConflictPolicy::SourceWins => SyncAction::Push {
            why: "this device's version wins by policy".to_owned(),
        },
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
            } else {
                SyncAction::Push {
                    why: format!("{ours_version} is not older than {theirs_version}"),
                }
            }
        }
        ConflictPolicy::KeepNewest => {
            if compare_versions(ours_version, theirs_version).is_gt() {
                SyncAction::Push {
                    why: format!("{ours_version} is newer than {theirs_version}"),
                }
            } else {
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
        let (core, pre) = version
            .split_once('-')
            .map_or((version, ""), |(core, pre)| (core, pre));
        let numbers = core
            .split(['.', '+'])
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect();
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
