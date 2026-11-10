use super::*;

impl EventService {
    /// Adapt event admission to the shared host-call error contract.
    ///
    /// # Errors
    /// The same classified refusals as emit, retaining bounded diagnostic details.
    pub fn emit_call(
        self: &Arc<Self>,
        plugin: &PluginId,
        event: &str,
        payload: &str,
    ) -> Result<(), synra_plugin_host::CallError> {
        self.emit(plugin, event, payload).map_err(|error| {
            let call = synra_plugin_host::CallError::new(error.code.as_str(), error.message);
            match error.details {
                Some(details) => call.with_details(details.to_string()),
                None => call,
            }
        })
    }
    /// Construct an inactive service. Binding it to a shared PluginSet enables delivery.
    #[must_use]
    pub fn new(db: Arc<Mutex<synra_store::SynraDb>>) -> Arc<Self> {
        Arc::new(Self {
            db,
            state: Mutex::new(State {
                runtime: None,
                plugins: Weak::new(),
                worker_running: false,
                stopping: false,
                pending: VecDeque::new(),
                bytes: 0,
                policies: VecDeque::new(),
                recent: VecDeque::new(),
                delivered: 0,
                refused: 0,
                unhandled: 0,
                metrics: None,
                remote_receipts: VecDeque::new(),
            }),
            wake: Condvar::new(),
        })
    }

    pub(crate) fn bind(
        &self,
        runtime: RequestId,
        plugins: Weak<Mutex<PluginSet>>,
        metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
    ) -> Result<(), SynraError> {
        let mut state = self.state.lock();
        if state.stopping || state.runtime.is_some_and(|bound| bound != runtime) {
            return Err(refusal(
                ErrorCode::Internal,
                "an event service belongs to one runtime and cannot be reused after shutdown",
                "runtimeMismatch",
            ));
        }
        state.runtime = Some(runtime);
        state.plugins = plugins;
        state.metrics = metrics;
        drop(state);
        Ok(())
    }

    /// Admit one local event from the currently executing guest. Success means queued, not delivered.
    ///
    /// # Errors
    /// Missing execution context, changed consent, undeclared events, invalid payloads and exhausted budgets are refused.
    pub fn emit(
        self: &Arc<Self>,
        plugin: &PluginId,
        event: &str,
        payload: &str,
    ) -> Result<(), SynraError> {
        let source = context::current()
            .filter(|execution| &execution.plugin == plugin)
            .ok_or_else(|| {
                refusal(
                    ErrorCode::CapabilityDenied,
                    "event emission requires a current guest execution",
                    "missingExecution",
                )
            })?;
        if payload.len() > synra_plugin_api::payload::MAX_PAYLOAD_BYTES {
            return Err(refusal(
                ErrorCode::PayloadTooLarge,
                "the event payload exceeds its byte budget",
                "payloadTooLarge",
            ));
        }
        let event = EventName::parse(event).map_err(policy::invalid)?;
        if !event.as_str().starts_with(&plugin.event_namespace()) {
            return Err(refusal(
                ErrorCode::CapabilityDenied,
                "a plugin may emit only its own event namespace",
                "foreignNamespace",
            ));
        }
        let payload_value: serde_json::Value = serde_json::from_str(payload).map_err(|_| {
            refusal(
                ErrorCode::InvalidArgument,
                "the event payload is not JSON",
                "invalidPayload",
            )
        })?;
        if !payload_value.is_object() {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "an event payload must be an object",
                "invalidPayload",
            ));
        }
        // The schema-less case uses the same structural and encoded-size budget.
        synra_plugin_api::payload::check_budget(&payload_value)
            .map_err(|error| policy::payload_error(&error))?;
        let (policy, grants) = self.policy(&source)?;
        policy::require(&grants, &format!("event:emit:{}", event.as_str()))?;
        policy.emitted(event.as_str(), &payload_value)?;
        let from = {
            let db = self.db.lock();
            let identity = db.identity().map_err(policy::storage)?.ok_or_else(|| {
                refusal(
                    ErrorCode::Internal,
                    "this host has no persisted identity",
                    "missingIdentity",
                )
            })?;
            drop(db);
            identity
                .device_id
                .parse::<DeviceId>()
                .map_err(policy::invalid)?
        };
        let cause = context::cause(source.runtime).next().ok_or_else(|| {
            refusal(
                ErrorCode::RateLimited,
                "the event chain exhausted its depth or emission budget",
                "eventChainLimit",
            )
        })?;
        self.enqueue(Pending {
            event,
            from,
            source: Origin::Local(source),
            request: RequestId::new(),
            trace: synra_observe::trace_scope::current().unwrap_or_default(),
            payload: payload_value,
            bytes: payload.len(),
            deadline: Instant::now() + EVENT_TTL,
            cause,
        })
    }

    fn enqueue(self: &Arc<Self>, pending: Pending) -> Result<(), SynraError> {
        let mut state = self.state.lock();
        self.enqueue_locked(&mut state, pending)?;
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    pub(in crate::plugin_events) fn enqueue_locked(
        self: &Arc<Self>,
        state: &mut State,
        pending: Pending,
    ) -> Result<(), SynraError> {
        if state.stopping
            || state.runtime != Some(pending.source.runtime())
            || state.plugins.strong_count() == 0
        {
            return Err(refusal(
                ErrorCode::Unsupported,
                "event delivery is not attached to this runtime",
                "workerUnavailable",
            ));
        }
        if state.pending.len() >= MAX_PENDING
            || state.bytes.saturating_add(pending.bytes) > MAX_QUEUED_BYTES
        {
            return Err(refusal(
                ErrorCode::RateLimited,
                "the event delivery queue is full",
                "eventQueueFull",
            ));
        }
        if !state.worker_running {
            state.worker_running = true;
            let service = Arc::clone(self);
            if std::thread::Builder::new()
                .name("synra-plugin-events".to_owned())
                .spawn(move || service.run())
                .is_err()
            {
                state.worker_running = false;
                return Err(refusal(
                    ErrorCode::Internal,
                    "the event worker could not start",
                    "workerUnavailable",
                ));
            }
        }
        state.bytes += pending.bytes;
        state.pending.push_back(pending);
        Ok(())
    }

    /// Snapshot counters and bounded decisions without exposing event values.
    #[must_use]
    pub fn report(&self) -> EventReport {
        let state = self.state.lock();
        EventReport {
            worker_running: state.worker_running,
            stopping: state.stopping,
            pending: state.pending.len(),
            queued_bytes: state.bytes,
            delivered: state.delivered,
            refused: state.refused,
            unhandled: state.unhandled,
            recent: state.recent.iter().cloned().collect(),
        }
    }

    /// Stop accepting events and wake the worker to discard queued payloads.
    /// An already running guest finishes under its existing call budget; this method does not block.
    pub fn stop(&self) {
        self.state.lock().stopping = true;
        self.wake.notify_all();
    }

    pub(crate) fn stop_runtime(&self, runtime: RequestId) {
        let mut state = self.state.lock();
        if state.runtime == Some(runtime) {
            state.stopping = true;
        }
        drop(state);
        self.wake.notify_all();
    }

    pub(in crate::plugin_events) fn record(
        &self,
        pending: &Pending,
        target: Option<PluginId>,
        error: Option<ErrorCode>,
        delivered: bool,
    ) {
        let target_label = target
            .as_ref()
            .map_or_else(|| "-".to_owned(), |id| id.as_str().to_owned());
        let error_label = error
            .as_ref()
            .map_or_else(|| "-".to_owned(), |code| code.as_str().to_owned());
        let mut state = self.state.lock();
        if delivered {
            state.delivered = state.delivered.saturating_add(1);
        } else if error.is_some() {
            state.refused = state.refused.saturating_add(1);
        } else {
            state.unhandled = state.unhandled.saturating_add(1);
        }
        if state.recent.len() >= 64 {
            state.recent.pop_front();
        }
        state.recent.push_back(Delivery {
            request_id: pending.request,
            trace_id: pending.trace,
            target,
            delivered,
            error,
        });
        let metrics = state.metrics.clone();
        drop(state);
        eprintln!(
            "synra: plugin event completed event={} request={} target={} delivered={} error={}",
            pending.event, pending.request, target_label, delivered, error_label,
        );
        if let Some(metrics) = metrics {
            let outcome = if delivered {
                "delivered"
            } else if error.is_some() {
                "refused"
            } else {
                "unhandled"
            };
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "plugin_event_deliveries_total",
                [("outcome".to_owned(), outcome.to_owned())],
            ));
        }
    }
}

pub(in crate::plugin_events) fn refusal(
    code: ErrorCode,
    message: impl Into<String>,
    kind: &str,
) -> SynraError {
    SynraError::new(code, message).with_details(serde_json::json!({"kind":kind}))
}
