use synra_protocol::{ErrorCode, PluginId};

use super::{Delivery, EventReport, EventService, Pending};

impl EventService {
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
