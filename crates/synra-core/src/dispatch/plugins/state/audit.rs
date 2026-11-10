use super::*;

impl PluginSet {
    /// What plugins have done, oldest first.
    #[must_use]
    pub fn audit(&self) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.all()
    }

    /// What one plugin has done, oldest first.
    #[must_use]
    pub fn audit_for(&self, id: &PluginId) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.for_plugin(id)
    }

    /// What one plugin had refused, which is what a user reads when asking why something did not work.
    #[must_use]
    pub fn refusals_for(&self, id: &PluginId) -> Vec<synra_observe::audit::AuditEntry> {
        self.audit.refusals_for_plugin(id)
    }

    /// Forgets one plugin's records, which is the user's "clear this plugin's history".
    ///
    /// # Why it is per plugin rather than whole-ring
    ///
    /// Because the screen an audit is read on is a plugin's card, and the action is taken beside one plugin's trail. A
    /// `clear()` of the whole ring would let the button on one card erase what the user was about to read on another.
    ///
    /// The counts go with the entries: a history the user cleared that still reports a total is one they did not clear.
    /// That detail belongs to `AuditRing::clear_plugin` rather than here, so the two readers of the ring cannot disagree
    /// about it.
    pub fn clear_audit(&mut self, id: &PluginId) {
        self.audit.clear_plugin(id);
    }

    /// Hands every record to a sink as well as to the ring.
    ///
    /// # Why the host installs one
    ///
    /// Because the ring is bounded (`synra_observe::audit::MEMORY_CAPACITY`) and lives in this process, so the audit a user
    /// sees is the recent history **of this run** — and the migration that created `plugin_audit` says what the table is
    /// for: *"the durable part is what makes the interface's 'recent activity' survive a restart."* A sink is how the two
    /// are the same trail rather than two.
    #[must_use]
    pub fn with_audit_sink(mut self, sink: AuditSink) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// The same set, telling a host when a plugin's health moves.
    #[must_use]
    pub fn with_health_sink(mut self, sink: HealthSink) -> Self {
        self.health_sink = Some(sink);
        self
    }

    /// The same set, counting the gate's decisions.
    ///
    /// # Why this is separate from the audit sink
    ///
    /// Because the two answer different questions and have different lifetimes. A sink is *what happened*, one row per call,
    /// written down and read by a person; a recorder is *how often*, aggregated, and read by a graph. A host may reasonably
    /// want one without the other — a diagnostic run wants numbers and no writes — and a single "observe this" switch would
    /// have made that impossible to express.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<synra_observe::metrics::RingRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Moves whatever a plugin recorded during its last call into the ring.
    ///
    /// Called once per call rather than from inside the host call, because the entries are produced while the guest runs
    /// and the set is borrowed by the caller for the duration. Draining after the fact is also what makes the buffer
    /// bounded in practice: it holds one call's worth of entries, not a process's.
    pub(in crate::dispatch::plugins) fn drain_audit(
        loaded: &mut Loaded,
        ring: &mut synra_observe::audit::AuditRing,
        sink: Option<&AuditSink>,
        trace: Option<synra_protocol::ids::TraceId>,
    ) {
        let entries = {
            let mut buffered = loaded.authority.audit.lock();
            if buffered.is_empty() {
                return;
            }
            std::mem::take(&mut *buffered)
        };
        for mut entry in entries {
            // ★ The trace is stamped here, on the entries this call produced. The gate inside the guest knows the
            // capability and the outcome; it has no way to know which user action the call belongs to, and a session is
            // installed once per pooled instance rather than once per call. The funnel that does know is this one.
            if entry.trace.is_none() {
                entry.trace = trace;
            }
            // ★ The sink is called **before** the record is moved into the ring, because the ring takes it by value. Both
            // get the same record: the ring is what the interface reads now, and the sink is what survives a restart. A
            // trail written to only one of them is a trail that disagrees with itself after a restart.
            if let Some(sink) = sink {
                sink(&entry);
            }
            ring.record(entry);
        }
    }

    /// Feeds one record to the drain, the way a gated call does.
    ///
    /// # ★ Why this exists, and why it is `#[cfg(test)]`
    ///
    /// The entries a sink receives are produced by a **real** component calling a host function. The scripted backend these
    /// tests use answers from a table, so no guest runs, no host function is called, and nothing is audited — which is why
    /// the first version of the sink test asserted the sink had seen something and seen nothing. A test of this seam has to
    /// put the record where a call puts it, and that is not an entry point production has any use for.
    ///
    /// # Returns
    ///
    /// `false` when no plugin by that name is loaded, so a caller cannot mistake "nothing happened" for "it was drained".
    #[cfg(test)]
    pub(crate) fn drain_record_for_test(
        &mut self,
        plugin: &PluginId,
        entry: synra_observe::audit::AuditEntry,
    ) -> bool {
        self.drain_record_with_trace_for_test(plugin, entry, None)
    }

    /// The same seam, with the trace a real call would pass.
    ///
    /// # Why the trace is a parameter of its own
    ///
    /// Because `drain_record_for_test` is called by tests that are not about traces, and a second entry point is cheaper
    /// than making every one of them pass `None` to say so. This is the one a test about stamping uses.
    #[cfg(test)]
    pub(crate) fn drain_record_with_trace_for_test(
        &mut self,
        plugin: &PluginId,
        entry: synra_observe::audit::AuditEntry,
        trace: Option<synra_protocol::ids::TraceId>,
    ) -> bool {
        // Destructured rather than reached through `self` three times: the drain needs the buffer, the ring and the sink at
        // once, and borrowing them from `self` separately is what the compiler refuses.
        let Self {
            loaded,
            audit,
            audit_sink,
            ..
        } = self;
        let Some(loaded) = loaded.get_mut(plugin) else {
            return false;
        };
        loaded.authority.audit.lock().push(entry);
        Self::drain_audit(loaded, audit, audit_sink.as_ref(), trace);
        true
    }
}
