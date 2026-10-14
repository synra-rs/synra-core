//! What is rate-limited, how much is allowed, and the refusal to serve.

use core::time::Duration;

use serde::{Deserialize, Serialize};
/// Which rate a call consumes from.
///
/// One bucket per kind rather than one bucket for everything: a plugin that emits a thousand events should not
/// thereby be unable to read a file. Separate buckets make each limit about the resource it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RateKind {
    /// Calls into the host at all, whatever they do.
    HostCalls,
    /// Events emitted.
    Events,
    /// Outbound network requests.
    NetworkRequests,
    /// Frames sent to other devices.
    DeviceSends,
    /// Filesystem operations.
    FsOps,
}

impl RateKind {
    /// Every kind, for iteration.
    pub const ALL: &'static [Self] = &[
        Self::HostCalls,
        Self::Events,
        Self::NetworkRequests,
        Self::DeviceSends,
        Self::FsOps,
    ];

    /// This kind's position in [`Self::ALL`].
    ///
    /// The variant order and the array order have to agree, which `every_rate_kind_has_a_quota_field` asserts.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::HostCalls => 0,
            Self::Events => 1,
            Self::NetworkRequests => 2,
            Self::DeviceSends => 3,
            Self::FsOps => 4,
        }
    }

    /// A name for a log line or a metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostCalls => "host-calls",
            Self::Events => "events",
            Self::NetworkRequests => "network-requests",
            Self::DeviceSends => "device-sends",
            Self::FsOps => "fs-ops",
        }
    }
}

/// How much of everything a plugin may use.
///
/// Every field is a supplied decision with a documented default, so a host that wants different numbers says so
/// rather than editing this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quota {
    // ── Static ──
    /// The most memory the plugin's instances may hold in total.
    pub max_memory_bytes: u64,
    /// The most instances that may exist at once.
    pub max_instances: u32,
    /// The most bytes the plugin may store in its sandbox.
    pub max_storage_bytes: u64,
    /// The most transfers that may be open at once.
    pub max_open_transfers: u32,
    // ── Rates ──
    /// Host calls per second.
    pub host_calls_per_sec: u32,
    /// The host-call burst allowance.
    pub host_calls_burst: u32,
    /// Events per second.
    pub events_per_sec: u32,
    /// Network requests per second.
    pub network_requests_per_sec: u32,
    /// Concurrent network requests.
    pub network_concurrent: u32,
    /// Device sends per second.
    pub device_sends_per_sec: u32,
    /// Filesystem operations per second.
    pub fs_ops_per_sec: u32,
    // ── One call ──
    /// The instruction budget for one call.
    pub call_fuel: u64,
    /// How long one call may take.
    pub call_timeout_ms: u64,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_instances: 4,
            max_storage_bytes: 64 * 1024 * 1024,
            max_open_transfers: 4,
            host_calls_per_sec: 500,
            host_calls_burst: 1_000,
            events_per_sec: 100,
            network_requests_per_sec: 10,
            network_concurrent: 4,
            device_sends_per_sec: 50,
            fs_ops_per_sec: 100,
            call_fuel: 100_000_000,
            call_timeout_ms: 2_000,
        }
    }
}

impl Quota {
    /// The default quota.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rate and burst for a kind.
    #[must_use]
    pub const fn rate_for(&self, kind: RateKind) -> (u32, u32) {
        match kind {
            RateKind::HostCalls => (self.host_calls_per_sec, self.host_calls_burst),
            // The other kinds have no separate burst in the design document, so the burst is the per-second rate:
            // a bucket that could hold a whole second's worth is already tolerant of ordinary bursts.
            RateKind::Events => (self.events_per_sec, self.events_per_sec),
            RateKind::NetworkRequests => (self.network_requests_per_sec, self.network_requests_per_sec),
            RateKind::DeviceSends => (self.device_sends_per_sec, self.device_sends_per_sec),
            RateKind::FsOps => (self.fs_ops_per_sec, self.fs_ops_per_sec),
        }
    }

    /// The quota a degraded plugin is held to.
    ///
    /// Half of everything. A linear reduction rather than a geometric one, because the purpose is to make the
    /// plugin's resource use stop growing — not to punish it. A plugin that halves its rate is doing nothing wrong.
    #[must_use]
    pub fn degraded(&self) -> Self {
        let halve_u32 = |value: u32| value / 2;
        let halve_u64 = |value: u64| value / 2;
        Self {
            max_memory_bytes: halve_u64(self.max_memory_bytes),
            max_instances: halve_u32(self.max_instances).max(1),
            max_storage_bytes: self.max_storage_bytes,
            max_open_transfers: halve_u32(self.max_open_transfers),
            host_calls_per_sec: halve_u32(self.host_calls_per_sec).max(1),
            host_calls_burst: halve_u32(self.host_calls_burst).max(1),
            events_per_sec: halve_u32(self.events_per_sec).max(1),
            network_requests_per_sec: halve_u32(self.network_requests_per_sec).max(1),
            network_concurrent: halve_u32(self.network_concurrent).max(1),
            device_sends_per_sec: halve_u32(self.device_sends_per_sec).max(1),
            fs_ops_per_sec: halve_u32(self.fs_ops_per_sec).max(1),
            call_fuel: halve_u64(self.call_fuel),
            // The timeout is not halved. A call that needs its time is not misbehaving by taking it, and shortening
            // the limit would turn a plugin that is merely slow into one that fails — which is a different problem
            // from the one degradation addresses.
            call_timeout_ms: self.call_timeout_ms,
        }
    }

    /// The per-call timeout.
    #[must_use]
    pub const fn call_timeout(&self) -> Duration {
        Duration::from_millis(self.call_timeout_ms)
    }
}
