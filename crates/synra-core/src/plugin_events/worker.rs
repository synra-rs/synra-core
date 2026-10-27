use super::{EventContext, EventService, Pending, context, policy, refusal};
use crate::dispatch::PluginSet;
use parking_lot::Mutex;
use std::{
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use synra_plugin_host::CallBudget;
use synra_protocol::{ErrorCode, SynraError};

struct Lease(Arc<EventService>);
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.0.state.lock();
        state.worker_running = false;
        let refused = u64::try_from(state.pending.len()).unwrap_or(u64::MAX);
        state.refused = state.refused.saturating_add(refused);
        state.pending.clear();
        state.bytes = 0;
        let metrics = state.metrics.clone();
        drop(state);
        self.0.wake.notify_all();
        if let Some(metrics) = metrics.filter(|_| refused > 0) {
            metrics.counter_add(
                &synra_observe::metrics::SeriesKey::new(
                    "plugin_event_deliveries_total",
                    [("outcome".to_owned(), "refused".to_owned())],
                ),
                refused,
            );
        }
    }
}

impl EventService {
    pub(super) fn run(self: Arc<Self>) {
        let _lease = Lease(Arc::clone(&self));
        loop {
            let next = {
                let mut state = self.state.lock();
                loop {
                    if state.stopping || state.plugins.strong_count() == 0 {
                        return;
                    }
                    if let Some(event) = state.pending.pop_front() {
                        state.bytes = state.bytes.saturating_sub(event.bytes);
                        let plugins = state.plugins.clone();
                        drop(state);
                        break Some((event, plugins));
                    }
                    self.wake.wait_for(&mut state, Duration::from_millis(100));
                }
            };
            let Some((pending, plugins)) = next else {
                return;
            };
            if let Err(error) = self.deliver(&pending, &plugins) {
                self.record(&pending, None, Some(error.code), false);
            }
        }
    }

    fn deliver(
        &self,
        pending: &Pending,
        plugins: &Weak<Mutex<PluginSet>>,
    ) -> Result<(), SynraError> {
        let plugins = plugins.upgrade().ok_or_else(stopped)?;
        if pending.deadline <= Instant::now() {
            return Err(expired());
        }
        let targets = {
            let set = plugins.lock();
            if !set.event_execution_current(&pending.source) {
                return Err(stopped());
            }
            set.event_executions()
        };
        let (source_policy, source_grants) = self.policy(&pending.source)?;
        policy::require(
            &source_grants,
            &format!("event:emit:{}", pending.event.as_str()),
        )?;
        source_policy.emitted(pending.event.as_str(), &pending.payload)?;
        let event_json = serde_json::to_string(&EventContext {
            event: &pending.event,
            from: pending.from,
            sender_plugin_id: &pending.source.plugin,
            request_id: pending.request,
            trace_id: pending.trace,
            payload: &pending.payload,
        })
        .map_err(policy::invalid)?;
        let mut matched = false;
        for target in targets {
            if pending.deadline <= Instant::now() {
                return Err(expired());
            }
            let (policy, grants) = match self.policy(&target) {
                Ok(policy) => policy,
                Err(error) => {
                    self.record(
                        pending,
                        Some(target.plugin.clone()),
                        Some(error.code),
                        false,
                    );
                    continue;
                }
            };
            if !policy.accepts(pending.event.as_str(), &pending.payload) {
                continue;
            }
            matched = true;
            let capability = format!("event:subscribe:{}", pending.event.as_str());
            if let Err(error) = policy::require(&grants, &capability) {
                self.record(
                    pending,
                    Some(target.plugin.clone()),
                    Some(error.code),
                    false,
                );
                continue;
            }
            if !pending.cause.take_delivery() {
                self.record(
                    pending,
                    Some(target.plugin.clone()),
                    Some(ErrorCode::RateLimited),
                    false,
                );
                continue;
            }
            let result = self.invoke(pending, &plugins, &target, &event_json);
            self.record(
                pending,
                Some(target.plugin.clone()),
                result.as_ref().err().map(|error| error.code),
                result.is_ok(),
            );
        }
        if !matched {
            self.record(pending, None, None, false);
        }
        Ok(())
    }

    fn invoke(
        &self,
        pending: &Pending,
        plugins: &Arc<Mutex<PluginSet>>,
        target: &Arc<context::Execution>,
        event_json: &str,
    ) -> Result<(), SynraError> {
        let mut set = plugins.lock();
        let stopping = self.state.lock().stopping;
        if stopping {
            return Err(stopped());
        }
        if !set.event_execution_current(&pending.source) || !set.event_execution_current(target) {
            return Err(stopped());
        }
        // Recheck persisted authority at the execution boundary, then release DB locks before Wasm.
        let (_, source_grants) = self.policy(&pending.source)?;
        policy::require(
            &source_grants,
            &format!("event:emit:{}", pending.event.as_str()),
        )?;
        let (_, grants) = self.policy(target)?;
        policy::require(
            &grants,
            &format!("event:subscribe:{}", pending.event.as_str()),
        )?;
        let remaining = pending
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(expired)?;
        let mut quota = set.quota(&target.plugin).ok_or_else(stopped)?;
        quota.call_timeout_ms = quota
            .call_timeout_ms
            .min(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX));
        if quota.call_timeout_ms == 0 {
            return Err(expired());
        }
        let _cause = context::enter_cause(pending.cause.clone());
        set.call_event(
            target,
            grants,
            event_json.to_owned(),
            CallBudget::from_quota(&quota),
            pending.trace,
        )
        .map_err(|error| SynraError::new(error.code(), error.to_string()))?
        .into_result()
        .map(|_| ())
    }
}

fn stopped() -> SynraError {
    refusal(
        ErrorCode::CapabilityDenied,
        "the event's runtime generation is no longer active",
        "executionChanged",
    )
}
fn expired() -> SynraError {
    refusal(
        ErrorCode::Timeout,
        "the queued event expired before execution",
        "eventExpired",
    )
}
