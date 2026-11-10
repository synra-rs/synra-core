use super::*;

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
