//! Authenticated plugin event admission and bounded asynchronous delivery through real guest entry points.

use crate::dispatch::PluginSet;
use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use synra_protocol::{
    event::EventName, DeviceId, ErrorCode, PluginId, RequestId, SynraError, TraceId,
};

pub(crate) mod context;
mod policy;
mod remote;
mod service;
mod worker;

pub(in crate::plugin_events) use service::refusal;

pub use remote::{
    answer_remote_event, RemoteAdmission, MAX_REMOTE_RECEIPTS, REMOTE_RECEIPT_EVENT,
    REMOTE_RECEIPT_TTL,
};

#[cfg(test)]
mod tests;

/// Maximum queued events for one host runtime.
pub const MAX_PENDING: usize = 128;
/// Maximum encoded payload bytes waiting for delivery.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
/// A queued event expires rather than running long after its producer disappeared.
pub const EVENT_TTL: Duration = Duration::from_secs(5);

/// The host-authenticated context delivered to lifecycle.on-event.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventContext<'a> {
    event: &'a EventName,
    from: DeviceId,
    sender_plugin_id: &'a PluginId,
    request_id: RequestId,
    trace_id: TraceId,
    payload: &'a serde_json::Value,
}

enum Origin {
    Local(Arc<context::Execution>),
    Remote {
        plugin: PluginId,
        peer: DeviceId,
        runtime: RequestId,
    },
}

impl Origin {
    fn plugin(&self) -> &PluginId {
        match self {
            Self::Local(execution) => &execution.plugin,
            Self::Remote { plugin, .. } => plugin,
        }
    }

    fn runtime(&self) -> RequestId {
        match self {
            Self::Local(execution) => execution.runtime,
            Self::Remote { runtime, .. } => *runtime,
        }
    }
}

struct Pending {
    event: EventName,
    from: DeviceId,
    source: Origin,
    request: RequestId,
    trace: TraceId,
    payload: serde_json::Value,
    bytes: usize,
    deadline: Instant,
    cause: context::Cause,
}

/// A delivery diagnostic that carries no event payload or guest return value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivery {
    /// The published event request.
    pub request_id: RequestId,
    /// Its original trace.
    pub trace_id: TraceId,
    /// The intended handler, or none for admission/expiry/unhandled outcomes.
    pub target: Option<PluginId>,
    /// Whether a guest handler actually completed successfully.
    pub delivered: bool,
    /// Classified refusal or failure, without sensitive payload values.
    pub error: Option<ErrorCode>,
}

/// Bounded diagnostics for the event worker.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventReport {
    /// Whether the worker is still running, including an in-flight handler.
    pub worker_running: bool,
    /// Whether shutdown was requested; no further event admission is allowed.
    pub stopping: bool,
    /// Events waiting for delivery.
    pub pending: usize,
    /// Encoded payload bytes in that queue.
    pub queued_bytes: usize,
    /// Successfully completed handler calls.
    pub delivered: u64,
    /// Refused, expired or failed deliveries.
    pub refused: u64,
    /// Published events with no matching handler.
    pub unhandled: u64,
    /// Most recent delivery decisions, oldest first, at most 64 entries.
    pub recent: Vec<Delivery>,
}

struct State {
    runtime: Option<RequestId>,
    plugins: Weak<Mutex<PluginSet>>,
    worker_running: bool,
    stopping: bool,
    pending: VecDeque<Pending>,
    bytes: usize,
    policies: VecDeque<Arc<policy::Policy>>,
    recent: VecDeque<Delivery>,
    delivered: u64,
    refused: u64,
    unhandled: u64,
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
    remote_receipts: VecDeque<remote::Receipt>,
}

/// Shared by a native host adapter and its plugin runtime; never calls a guest under a queue or DB lock.
pub struct EventService {
    db: Arc<Mutex<synra_store::SynraDb>>,
    state: Mutex<State>,
    wake: Condvar,
}
