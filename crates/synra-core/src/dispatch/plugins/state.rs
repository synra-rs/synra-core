use super::*;

/// The plugins this kernel can ask.
///
/// # Why this is not `Clone`
///
/// Because it holds live instances. A Wasm store has fuel, memory and guest globals in it, and a copy of one is not a
/// second store — it is the same store under a second name, which is how two callers end up corrupting one guest's
/// state. The backend is shared deliberately and cheaply; the set of instances is not shared at all.
pub struct PluginSet {
    pub(super) runtime_id: synra_protocol::RequestId,
    pub(super) events: Option<Arc<crate::plugin_events::EventService>>,
    pub(super) backend: Backend,
    pub(super) loaded: HashMap<PluginId, Loaded>,
    /// Where a plugin's effects reach.
    ///
    /// ★ The piece that was missing, and the reason the capability gate never ran. Every instance used to be created
    /// with `session: None`, and `linker::run` refuses **every** host call when there is no session — so no plugin could
    /// reach a host function at all and nothing was audited. The gate is the mechanism the whole capability model rests
    /// on, and it was inert.
    pub(super) host: Arc<dyn synra_plugin_host::host_calls::Host>,
    /// What plugins have done, bounded and readable.
    ///
    /// The kernel already has a ring for this ([`synra_observe::audit::AuditRing`]); what it did not have was a writer,
    /// because the only path to one was `synra_core::Kernel::record_action`, and no host constructs that type.
    pub(super) audit: synra_observe::audit::AuditRing,
    /// Where a record goes besides the ring, when a host has somewhere to put it.
    ///
    /// ★ Why this is a callback rather than a store handle
    ///
    /// Because the kernel is what decides that a call is auditable, and the **host** is what has a database. `synra-core`
    /// depends on neither `rusqlite` nor a path, so the only honest way to hand a record on is to be given somewhere to put
    /// it — which is the same split as `decide` returning an envelope it cannot send and the daemon sending it.
    ///
    /// `None` is the ordinary state for a kernel with nowhere durable to write: a test, or a build whose store is not
    /// open. The ring still fills, so the audit the interface shows is complete for this process either way.
    pub(super) audit_sink: Option<AuditSink>,
    /// Where the gate's counters go, when the kernel keeps numbers.
    ///
    /// Shared rather than one per plugin, because the design's `gate_*` metrics are read as one series across plugins: the
    /// plugin is a **label** on a series, not a series of its own.
    pub(super) metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
    /// Where a health change goes, when a host has a window to tell.
    ///
    /// ★ Why this is a callback and not an event type here: `synra-core` does not own the event contract, and a kernel
    /// that constructed IPC events would depend on the interface's vocabulary. The host passes what it wants done; the
    /// event's field names are the host's business.
    pub(super) health_sink: Option<HealthSink>,
}

/// Where one health change goes.
///
/// The arguments are the plugin, the new rung's `snake_case` name and the ladder's own explanation. A boxed closure with
/// three arguments rather than a trait, for the same reason [`AuditSink`] is one: there is exactly one thing it can do.
pub type HealthSink = Arc<dyn Fn(&PluginId, &str, &str) + Send + Sync>;

/// Where one audit record goes, besides the ring.
///
/// A boxed closure rather than a trait, because there is exactly one thing it can do — take a record — and a trait with one
/// method would be a name for the same signature. `Send + Sync` because the set is behind a lock that callers on several
/// threads take.
pub type AuditSink = Arc<dyn Fn(&synra_observe::audit::AuditEntry) + Send + Sync>;

impl fmt::Debug for PluginSet {
    /// Deliberately not derived.
    ///
    /// A derived `Debug` would need `Loaded: Debug`, and getting there would mean printing compiled artifacts and live
    /// instances. What is useful in a log is the shape of the table — which plugins, at which versions, with how many
    /// instances — and that is what this writes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSet")
            .field("engine", &self.backend.kind())
            .field("plugins", &self.ids())
            .finish()
    }
}

impl Drop for PluginSet {
    fn drop(&mut self) {
        if let Some(events) = &self.events {
            events.stop_runtime(self.runtime_id);
        }
    }
}

impl PluginSet {
    /// Use the same bounded local event service as this set's native host adapter.
    #[must_use]
    pub fn with_event_delivery(mut self, events: Arc<crate::plugin_events::EventService>) -> Self {
        self.events = Some(events);
        self
    }

    /// Clone the bound event admission service without retaining the plugin runtime lock.
    #[must_use]
    pub fn event_service(&self) -> Option<Arc<crate::plugin_events::EventService>> {
        self.events.clone()
    }

    /// Share the runtime and bind its event worker before activating plugins.
    ///
    /// # Errors
    /// Refuses reusing an event service for another runtime or after shutdown.
    pub fn into_shared(self) -> Result<Arc<Mutex<Self>>, synra_protocol::SynraError> {
        let runtime = self.runtime_id;
        let events = self.events.clone();
        let metrics = self.metrics.clone();
        let shared = Arc::new(Mutex::new(self));
        if let Some(events) = events {
            events.bind(runtime, Arc::downgrade(&shared), metrics)?;
        }
        Ok(shared)
    }

    pub(crate) fn event_executions(&self) -> Vec<Arc<crate::plugin_events::context::Execution>> {
        let mut executions: Vec<_> = self
            .loaded
            .values()
            .filter(|loaded| matches!(loaded.lifecycle.state(), State::Active { .. }))
            .map(|loaded| Arc::clone(&loaded.execution))
            .collect();
        executions.sort_by(|left, right| left.plugin.cmp(&right.plugin));
        executions
    }

    pub(crate) fn event_execution_current(
        &self,
        execution: &Arc<crate::plugin_events::context::Execution>,
    ) -> bool {
        self.loaded.get(&execution.plugin).is_some_and(|loaded| {
            Arc::ptr_eq(&loaded.execution, execution)
                && matches!(loaded.lifecycle.state(), State::Active { .. })
        })
    }

    pub(crate) fn call_event(
        &mut self,
        execution: &Arc<crate::plugin_events::context::Execution>,
        grants: CapabilitySet,
        event_json: String,
        budget: CallBudget,
        trace: synra_protocol::TraceId,
    ) -> Result<CallOutcome, PluginSetError> {
        if !self.event_execution_current(execution) {
            return Err(PluginSetError::NotLoaded {
                id: execution.plugin.clone(),
            });
        }
        if let Some(loaded) = self.loaded.get_mut(&execution.plugin) {
            loaded.authority.grants = grants;
        }
        self.call_traced(
            &execution.plugin,
            &synra_plugin_host::Work::Event { event_json },
            budget,
            u64::try_from(synra_store::sqlite::now_ms()).unwrap_or_default(),
            Some(trace),
        )
    }

    /// The health a loaded plugin is in **right now**.
    ///
    /// ★ Why this accessor had to exist for the ladder to mean anything.
    ///
    /// Round 114 made a trap count towards the ladder and found that nothing could read the result: the daemon's `status`
    /// reports the **database row**, recorded at install time, and the live rung was unreachable. A mechanism whose state
    /// has no reader is one nobody can act on — and the point of telling a user their plugin is degrading is that they act
    /// before it is disabled.
    ///
    /// `None` for a plugin that is not loaded, which is a different fact from "healthy".
    #[must_use]
    pub fn health_of(&self, id: &str) -> Option<Health> {
        let id = PluginId::try_from(id.to_owned()).ok()?;
        self.loaded
            .get(&id)
            .map(|loaded| loaded.authority.budget.health())
    }

    /// The quota report of a loaded plugin, for a screen that shows its health.
    ///
    /// The rung alone is what [`PluginSet::health_of`] answers; this is the rung plus the sentence, the call counts and the
    /// quota in force — the facts a card needs to say *why* a plugin is degraded rather than only that it is.
    pub fn report_of(&self, id: &str) -> Option<synra_plugin_host::quota::QuotaReport> {
        let id = PluginId::try_from(id.to_owned()).ok()?;
        self.loaded
            .get(&id)
            .map(|loaded| loaded.authority.budget.report())
    }

    /// A set with no plugins, over a given engine and reaching a given host.
    ///
    /// # Why the host is required rather than defaulted
    ///
    /// Because there is no honest default. An instance with no session refuses every host call, so a set built without a
    /// host would be one whose plugins can do nothing — and the failure would read as a plugin problem rather than as a
    /// host that never said where its effects should go. Requiring it makes each caller state what its host is, which is
    /// the same reason `PluginSpec` has no default grants.
    #[must_use]
    pub fn new(backend: Backend, host: Arc<dyn synra_plugin_host::host_calls::Host>) -> Self {
        Self {
            runtime_id: synra_protocol::RequestId::new(),
            events: None,
            backend,
            loaded: HashMap::new(),
            host,
            audit: synra_observe::audit::AuditRing::new(),
            audit_sink: None,
            metrics: None,
            health_sink: None,
        }
    }

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
    pub(super) fn drain_audit(
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

    /// The engine these plugins run on.
    #[must_use]
    pub const fn backend(&self) -> &Backend {
        &self.backend
    }

    /// How many plugins are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    /// Whether a plugin is loaded.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.loaded.contains_key(id)
    }

    /// The loaded plugins, in a stable order.
    ///
    /// Sorted rather than in insertion order because two calls that read the same table should print the same line, and
    /// a `HashMap`'s order is not a thing a reader can hold in their head.
    #[must_use]
    pub fn ids(&self) -> Vec<PluginId> {
        let mut ids: Vec<PluginId> = self.loaded.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// What a plugin has been granted.
    #[must_use]
    pub fn grants(&self, id: &PluginId) -> Option<&CapabilitySet> {
        self.loaded.get(id).map(|loaded| &loaded.authority.grants)
    }

    /// The host every plugin instance reaches.
    ///
    /// # Why this is public
    ///
    /// Because the UI channel answers some calls **through the same host the Wasm half uses** — `network.fetch` is the
    /// first. A second fetcher built in the shell would have its own in-flight limit and its own reading of the grants,
    /// so one plugin page and one plugin instance could exceed together what neither may alone, and the two could
    /// disagree about which hosts the user allowed.
    ///
    /// It is `&Arc` rather than the trait object so a caller can clone it and **drop this set's lock** before doing
    /// network work: a fetch held under the plugin lock would make every other plugin command wait for the network.
    #[must_use]
    pub fn host(&self) -> &Arc<dyn synra_plugin_host::host_calls::Host> {
        &self.host
    }
}
