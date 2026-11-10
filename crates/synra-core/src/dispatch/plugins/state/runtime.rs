use super::*;

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
}
