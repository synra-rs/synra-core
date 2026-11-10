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
