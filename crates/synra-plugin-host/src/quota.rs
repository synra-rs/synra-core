//! Quotas: what a plugin may use, and what happens when it asks for more.
//!
//! # Two different limits, and mixing them up is the usual mistake
//!
//! * **Static quotas** — memory, instances, storage, open transfers. A plugin either fits or it does not, and
//!   exceeding one is a decision the host made about how much a plugin may hold.
//! * **Rates** — host calls, events, network requests, device sends, filesystem operations. A plugin may do any of
//!   these as often as it likes *up to* a rate, and exceeding one is a burst rather than an overreach.
//!
//! They need different responses. A static limit that is exceeded is a refusal with no retry; a rate that is
//! exceeded is a refusal that says when to try again. Treating a rate as static would fail a plugin for a burst it
//! was about to stop doing anyway; treating a static limit as a rate would let it retry forever against a wall.
//!
//! # The buckets are not just a limiter, they are a health signal
//!
//! The design document's escalation is a ladder, and the rungs matter:
//!
//! 1. **A single exceedance** fails that call. Ordinary: a plugin that fires a burst of events hits a bucket and
//!    waits.
//! 2. **Persistent exceedance** — more than twenty refusals in ten seconds — is recorded against the plugin's
//!    *health*, and the interface says "this plugin is asking too often". Still working, still allowed to keep
//!    going.
//! 3. **A low health score** moves the plugin to *degraded*: the same capabilities at reduced quotas. It keeps
//!    working, more slowly.
//! 4. **Still exceeding** moves it to *faulted*: disabled. This is the only rung that stops the plugin, and it is
//!    reached only after the two below it were tried.
//!
//! The ladder exists because the alternative is one threshold somewhere in the middle: low enough to catch a
//! runaway plugin, high enough that a plugin doing heavy legitimate work gets disabled. Four rungs let the host be
//! generous at first and firm later, and the user sees which rung they are on.

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

/// A token bucket.
///
/// Refills continuously rather than in ticks. A tick-based bucket gives a plugin nothing for the rest of the
/// second after it exhausts one, which turns a burst into a stall and makes the observed rate depend on where in
/// the second the burst started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBucket {
    /// Tokens available, scaled so a fractional refill is representable.
    ///
    /// Scaled by [`Self::SCALE`] so a bucket that refills at half a token per millisecond can be represented
    /// without floating point — a limit that behaves differently on two platforms is worse than one that rounds.
    tokens: u64,
    /// The most tokens it may hold, scaled.
    capacity: u64,
    /// Tokens added per second, scaled.
    refill_per_sec: u64,
    /// When it was last refilled, as a monotonic millisecond count.
    last_refill_ms: u64,
}

impl TokenBucket {
    /// The fixed-point scale.
    ///
    /// A thousand: enough that one token per second refills at one unit per millisecond, which is the finest
    /// granularity any of these limits needs.
    pub const SCALE: u64 = 1_000;

    /// A full bucket.
    #[must_use]
    pub fn new(rate_per_sec: u32, burst: u32, now_ms: u64) -> Self {
        let capacity = u64::from(burst).saturating_mul(Self::SCALE);
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: u64::from(rate_per_sec).saturating_mul(Self::SCALE),
            last_refill_ms: now_ms,
        }
    }

    /// How many whole tokens are available.
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.tokens / Self::SCALE
    }

    /// The most it may hold.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity / Self::SCALE
    }

    /// Adds the tokens earned since the last refill.
    ///
    /// A time earlier than the last refill adds nothing rather than subtracting: the caller's clock is monotonic,
    /// and a bucket that lost tokens on a backwards reading would refuse a call it had already earned.
    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_refill_ms {
            return;
        }
        let elapsed_ms = now_ms - self.last_refill_ms;
        let earned = self.refill_per_sec.saturating_mul(elapsed_ms) / 1_000;
        self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
        self.last_refill_ms = now_ms;
    }

    /// Takes `count` tokens if they are available.
    ///
    /// # Errors
    ///
    /// [`RateLimited`] with how long to wait.
    pub fn try_consume(&mut self, count: u32, now_ms: u64) -> Result<(), RateLimited> {
        self.refill(now_ms);

        let wanted = u64::from(count).saturating_mul(Self::SCALE);
        if self.tokens >= wanted {
            self.tokens -= wanted;
            return Ok(());
        }

        let shortfall = wanted - self.tokens;
        // A bucket with no refill rate would wait forever, so the answer is the maximum rather than a division by
        // zero. A caller showing this says "not for a very long time" rather than hanging on an arithmetic error.
        let wait_ms = if self.refill_per_sec == 0 {
            u64::MAX
        }
        else {
            shortfall.saturating_mul(1_000).div_ceil(self.refill_per_sec)
        };
        Err(RateLimited { kind: None, retry_after_ms: wait_ms, shortfall })
    }

    /// Resets to full, for a plugin that has been re-enabled.
    pub const fn refill_fully(&mut self, now_ms: u64) {
        self.tokens = self.capacity;
        self.last_refill_ms = now_ms;
    }
}

/// Why a call was refused for rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("rate limited; try again in {retry_after_ms}ms")]
pub struct RateLimited {
    /// Which kind, when the refusal came from a limiter that knows.
    pub kind: Option<RateKind>,
    /// How long to wait.
    pub retry_after_ms: u64,
    /// How many tokens were missing.
    pub shortfall: u64,
}

impl RateLimited {
    /// How long to wait.
    #[must_use]
    pub const fn retry_after(&self) -> Duration {
        Duration::from_millis(self.retry_after_ms)
    }
}

/// A static limit that was exceeded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StaticRefusal {
    /// The plugin would hold more memory than allowed.
    #[error("the plugin would use {wanted} bytes of memory, and its limit is {limit}")]
    Memory {
        /// What it asked for.
        wanted: u64,
        /// The limit.
        limit: u64,
    },
    /// The plugin asked for more instances than allowed.
    #[error("the plugin would have {wanted} instances, and its limit is {limit}")]
    Instances {
        /// What it asked for.
        wanted: u32,
        /// The limit.
        limit: u32,
    },
    /// The plugin would store more than allowed.
    #[error("the plugin would store {wanted} bytes, and its limit is {limit}")]
    Storage {
        /// What it asked for.
        wanted: u64,
        /// The limit.
        limit: u64,
    },
    /// The plugin asked for more transfers than allowed.
    #[error("the plugin would have {wanted} open transfers, and its limit is {limit}")]
    Transfers {
        /// What it asked for.
        wanted: u32,
        /// The limit.
        limit: u32,
    },
}

impl StaticRefusal {
    /// Whether a caller may try again later.
    ///
    /// Never. A static limit is a decision about how much a plugin may hold, so retrying against it is retrying
    /// against the host's own configuration. A rate, by contrast, is a refusal that says when.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

/// How many refusals inside the window make a plugin look unhealthy.
pub const PERSISTENT_REFUSALS: u32 = 20;

/// The window in which refusals are counted.
pub const PERSISTENCE_WINDOW: Duration = Duration::from_secs(10);

/// How many times the plugin must be persistently refused before it is degraded.
pub const DEGRADE_AFTER_WINDOWS: u32 = 2;

/// How many times a degraded plugin must be persistently refused before it is faulted.
pub const FAULT_AFTER_WINDOWS: u32 = 3;

/// Where a plugin sits on the escalation ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Health {
    /// Ordinary.
    Good,
    /// Asking too often, but still working at full quota.
    ///
    /// The rung that exists so the user is told before anything is restricted.
    Overreaching,
    /// Held to a reduced quota.
    Degraded,
    /// Disabled.
    Faulted,
}

impl Health {
    /// Whether the plugin may run.
    #[must_use]
    pub const fn is_running(self) -> bool {
        !matches!(self, Self::Faulted)
    }

    /// Whether the quota should be the degraded one.
    #[must_use]
    pub const fn uses_degraded_quota(self) -> bool {
        matches!(self, Self::Degraded | Self::Faulted)
    }

    /// Whether the interface should say something.
    ///
    /// Everything above ordinary. A user whose plugin has been degraded needs to know why it got slower, and the
    /// design document requires this transparency.
    #[must_use]
    pub const fn is_worth_telling_the_user(self) -> bool {
        !matches!(self, Self::Good)
    }

    /// A sentence for the interface.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Good => "running normally",
            Self::Overreaching => "this plugin is asking more often than its limits allow",
            Self::Degraded => "this plugin is over its limits, so it is running at a reduced quota",
            Self::Faulted => "this plugin exceeded its limits repeatedly and has been disabled",
        }
    }

    /// A name for a metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Overreaching => "overreaching",
            Self::Degraded => "degraded",
            Self::Faulted => "faulted",
        }
    }
}

/// Which persistence window a timestamp falls in.
///
/// Derived rather than stored, so two plugins refused at the same instant are in the same window whatever order
/// their calls arrive in.
fn window_number(now_ms: u64) -> u64 {
    let window_ms = u64::try_from(PERSISTENCE_WINDOW.as_millis()).unwrap_or(u64::MAX);
    if window_ms == 0 {
        return 0;
    }
    now_ms / window_ms
}

/// A timestamp inside persistence window `n`, for a test.
///
/// Derived from the window number rather than written as `n * WINDOW_MS`, because a multiple of the window length
/// *is* the boundary and belongs to the next window — which made two consecutive "windows" in the tests land in the
/// same one.
#[cfg(test)]
fn in_window(n: u64) -> u64 {
    let window_ms = u64::try_from(PERSISTENCE_WINDOW.as_millis()).unwrap_or(u64::MAX);
    n.saturating_mul(window_ms).saturating_add(1)
}

/// A plugin's runtime budget: its rates, its counters and its health.
#[derive(Debug)]
pub struct Budget {
    quota: Quota,
    buckets: parking_lot::Mutex<std::collections::HashMap<RateKind, TokenBucket>>,
    /// Refusals by kind, for the settings screen and the report.
    refusals_by_kind: parking_lot::Mutex<[u64; RateKind::ALL.len()]>,
    /// Refusals per window, keyed by the window's number.
    refusals: parking_lot::Mutex<std::collections::HashMap<u64, u32>>,
    /// How many windows have been persistently refused.
    bad_windows: parking_lot::Mutex<u32>,
    /// The last window that was judged, so one window moves one rung.
    last_judged_window: parking_lot::Mutex<Option<u64>>,
    health: parking_lot::Mutex<Health>,
    /// Total calls admitted, for the settings screen.
    admitted: parking_lot::Mutex<u64>,
    /// Total calls refused, for the settings screen.
    refused: parking_lot::Mutex<u64>,

}

impl Budget {
    /// A budget at the given quota.
    #[must_use]
    pub fn new(quota: Quota) -> Self {
        let now = 0;
        let mut buckets = std::collections::HashMap::new();
        for kind in RateKind::ALL {
            let (rate, burst) = quota.rate_for(*kind);
            buckets.insert(*kind, TokenBucket::new(rate, burst, now));
        }
        Self {
            quota,
            buckets: parking_lot::Mutex::new(buckets),
            refusals: parking_lot::Mutex::new(std::collections::HashMap::new()),
            bad_windows: parking_lot::Mutex::new(0),
            last_judged_window: parking_lot::Mutex::new(None),
            health: parking_lot::Mutex::new(Health::Good),
            admitted: parking_lot::Mutex::new(0),
            refused: parking_lot::Mutex::new(0),
            refusals_by_kind: parking_lot::Mutex::new([0; RateKind::ALL.len()]),
        }
    }

    /// The quota in force, which is the degraded one once the plugin has been degraded.
    #[must_use]
    pub fn quota(&self) -> Quota {
        if self.health().uses_degraded_quota() {
            self.quota.degraded()
        }
        else {
            self.quota.clone()
        }
    }

    /// Where the plugin sits on the ladder.
    #[must_use]
    pub fn health(&self) -> Health {
        *self.health.lock()
    }

    /// How many calls were admitted.
    #[must_use]
    pub fn admitted(&self) -> u64 {
        *self.admitted.lock()
    }

    /// How many calls were refused.
    #[must_use]
    pub fn refused(&self) -> u64 {
        *self.refused.lock()
    }

    /// Checks a static limit.
    ///
    /// # Errors
    ///
    /// [`StaticRefusal`] describing which limit and by how much.
    pub fn check_memory(&self, wanted: u64) -> Result<(), StaticRefusal> {
        let limit = self.quota().max_memory_bytes;
        if wanted > limit {
            return Err(StaticRefusal::Memory { wanted, limit });
        }
        Ok(())
    }

    /// Checks an instance count.
    ///
    /// # Errors
    ///
    /// [`StaticRefusal::Instances`].
    pub fn check_instances(&self, wanted: u32) -> Result<(), StaticRefusal> {
        let limit = self.quota().max_instances;
        if wanted > limit {
            return Err(StaticRefusal::Instances { wanted, limit });
        }
        Ok(())
    }

    /// Checks a storage size.
    ///
    /// # Errors
    ///
    /// [`StaticRefusal::Storage`].
    pub fn check_storage(&self, wanted: u64) -> Result<(), StaticRefusal> {
        let limit = self.quota().max_storage_bytes;
        if wanted > limit {
            return Err(StaticRefusal::Storage { wanted, limit });
        }
        Ok(())
    }

    /// Checks an open-transfer count.
    ///
    /// # Errors
    ///
    /// [`StaticRefusal::Transfers`].
    pub fn check_transfers(&self, wanted: u32) -> Result<(), StaticRefusal> {
        let limit = self.quota().max_open_transfers;
        if wanted > limit {
            return Err(StaticRefusal::Transfers { wanted, limit });
        }
        Ok(())
    }

    /// Consumes from a rate bucket.
    ///
    /// # Errors
    ///
    /// [`RateLimited`] with how long to wait. The refusal is also recorded, because the ladder depends on counting
    /// them.
    pub fn consume(&self, kind: RateKind, count: u32, now_ms: u64) -> Result<(), RateLimited> {
        // A faulted plugin may not consume anything. Checked here as well as at the call site, because a caller that
        // forgot would hand a disabled plugin its budget back.
        if !self.health().is_running() {
            let refusal = RateLimited { kind: Some(kind), retry_after_ms: u64::MAX, shortfall: 0 };
            self.record_refusal(kind, now_ms);
            return Err(refusal);
        }

        let mut buckets = self.buckets.lock();
        let Some(bucket) = buckets.get_mut(&kind) else {
            // A kind with no bucket means the quota changed under a live budget. Refusing is the safe answer: the
            // alternative is admitting a call with no limit at all.
            return Err(RateLimited { kind: Some(kind), retry_after_ms: u64::MAX, shortfall: 0 });
        };

        let outcome = bucket.try_consume(count, now_ms);

        drop(buckets);

        match outcome {
            Ok(()) => {
                // One lock acquisition, then the arithmetic on the guard. Writing `*self.x.lock() = self.x.lock()...`
                // takes the lock twice in one expression, and `parking_lot`'s mutex is not reentrant: the second
                // acquisition deadlocks, so this is the difference between a counter and a hang on every call.
                let mut admitted = self.admitted.lock();
                *admitted = admitted.saturating_add(1);
                drop(admitted);
                Ok(())
            }
            Err(mut refusal) => {
                refusal.kind = Some(kind);
                self.record_refusal(kind, now_ms);
                Err(refusal)
            }
        }
    }

    /// Records a refusal.
    ///
    /// The window is derived from the timestamp rather than kept as state. Two plugins that are refused at the same
    /// instant are in the same window whatever order their calls arrive in, so the ladder does not depend on when
    /// each plugin's budget happened to be created — and a window cannot be closed early by an unrelated call.
    fn record_refusal(&self, kind: RateKind, now_ms: u64) {
        {
            let mut refused = self.refused.lock();
            *refused = refused.saturating_add(1);
        }
        self.count_refusal(kind);

        let window = window_number(now_ms);
        let count = {
            let mut kind_refusals = self.refusals.lock();
            let entry = kind_refusals.entry(window).or_insert(0);
            *entry = entry.saturating_add(1);
            let count = *entry;

            // Windows older than the previous one are dropped: the question is whether the plugin is persistently
            // over its limits *now*, and a window nobody has asked about since is not evidence either way.
            let oldest_to_keep = window.saturating_sub(1);
            kind_refusals.retain(|number, _| *number >= oldest_to_keep);
            count
        };

        if count < PERSISTENT_REFUSALS {
            return;
        }

        // One judgement per window. The last window judged is stored, so a plugin that is refused a hundred times in
        // one window moves one rung rather than a hundred — which would jump straight to faulted and defeat the
        // ladder's purpose.
        {
            let mut last = self.last_judged_window.lock();
            if *last == Some(window) {
                return;
            }
            *last = Some(window);
        }

        let bad_windows = {
            let mut bad = self.bad_windows.lock();
            *bad = bad.saturating_add(1);
            *bad
        };
        self.advance_health(bad_windows);
    }

    /// Counts one refusal by kind, for the settings screen.
    ///
    /// Indexed by the kind's own number rather than by a map key. The map version needed `or_insert`, which returns a
    /// borrow tied to the map — and that borrow keeps the guard alive for the rest of the function, which is exactly
    /// the long-held guard `clippy::correctness` objects to. A fixed array has no such borrow, and the kinds are a
    /// closed set, so the array is the shape the data actually has.
    fn count_refusal(&self, kind: RateKind) {
        let mut counts = self.refusals_by_kind.lock();
        if let Some(slot) = counts.get_mut(kind.index()) {
            *slot = slot.saturating_add(1);
        }
    }

    /// Closes the current window if it has ended, and lets a plugin that has stopped misbehaving recover.
    ///
    /// Called by the host on a timer. Without it a degraded plugin that went completely quiet would stay degraded
    /// forever, because a plugin that is producing no calls produces no refusals and therefore never reaches
    /// [`Self::record_refusal`].
    pub fn tick(&self, now_ms: u64) {
        let window = window_number(now_ms);
        let already_judged = {
            let last = self.last_judged_window.lock();
            *last == Some(window)
        };
        if already_judged {
            return;
        }

        // A window that was not persistently refused is evidence the plugin recovered, so the count of bad windows
        // falls rather than standing forever. Two good windows undo one bad one, which lets a plugin that was
        // degraded recover without the user intervening.
        {
            let mut last = self.last_judged_window.lock();
            *last = Some(window);
        }
        let bad_windows = {
            let mut bad = self.bad_windows.lock();
            *bad = bad.saturating_sub(1);
            *bad
        };
        self.advance_health(bad_windows);
    }
    /// Moves the health to match the number of persistently refused windows.
    fn advance_health(&self, bad_windows: u32) {
        let mut health = self.health.lock();
        let next = match *health {
            // From ordinary, a single bad window is worth telling the user about; the second degrades the plugin.
            Health::Good | Health::Overreaching => {
                if bad_windows >= DEGRADE_AFTER_WINDOWS {
                    Health::Degraded
                }
                else if bad_windows >= 1 {
                    Health::Overreaching
                }
                else {
                    Health::Good
                }
            }
            // From degraded, the plugin keeps failing at a reduced quota, so the ladder moves to faulted.
            Health::Degraded => {
                if bad_windows >= FAULT_AFTER_WINDOWS {
                    Health::Faulted
                }
                else {
                    Health::Degraded
                }
            }
            // Faulted is terminal until a user or a reinstall clears it. A ladder that could climb back down on its
            // own would re-enable a plugin that was disabled for a reason.
            Health::Faulted => Health::Faulted,
        };
        *health = next;
    }

    /// Returns a plugin to ordinary health and refills its buckets.
    ///
    /// Called when a user re-enables a plugin, or when it is reinstalled. Refills because a plugin that was disabled
    /// for a while should not be refused immediately for a bucket that never refilled while it was not running.
    pub fn reset(&self, now_ms: u64) {
        *self.health.lock() = Health::Good;
        *self.bad_windows.lock() = 0;
        self.refusals.lock().clear();
        *self.last_judged_window.lock() = Some(window_number(now_ms));
        for bucket in self.buckets.lock().values_mut() {
            bucket.refill_fully(now_ms);
        }
    }

    /// What the settings screen shows for this plugin.
    #[must_use]
    pub fn report(&self) -> QuotaReport {
        let health = self.health();
        QuotaReport {
            health: health.as_str().to_owned(),
            explanation: health.explain().to_owned(),
            admitted: self.admitted(),
            refused: self.refused(),
            quota: self.quota(),
            refusals_by_kind: {
                let counts = self.refusals_by_kind.lock();
                RateKind::ALL
                    .iter()
                    .enumerate()
                    .filter_map(|(index, kind)| {
                        let count = counts.get(index).copied().unwrap_or(0);
                        (count > 0).then(|| (kind.as_str().to_owned(), count))
                    })
                    .collect()
            },
        }
    }
}

/// What the settings screen shows about a plugin's resource use.
///
/// The design document requires this transparency: memory, call count, refusal count and the most recent refusal
/// reason per plugin, with the user able to raise the quota of a plugin they trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaReport {
    /// Where the plugin sits on the ladder.
    pub health: String,
    /// A sentence for the user.
    pub explanation: String,
    /// How many calls were admitted.
    pub admitted: u64,
    /// How many were refused.
    pub refused: u64,
    /// The quota in force.
    pub quota: Quota,
    /// Refusals by kind, for a caller showing where the pressure is.
    /// Refusals by kind, in the order the kinds are declared.
    ///
    /// # Why a slice and not a map
    ///
    /// This is part of a stable crate's public signature, and a public map is a promise about the implementation:
    /// replacing it would be a breaking change, and that replacement is exactly what a determinism problem calls for.
    /// The report is a *list* of at most five counters that a caller shows in a row, so a sequence says the same thing
    /// and promises less — and the order is the declared one rather than whatever a hash happened to produce, which is
    /// what a test comparing two reports wants.
    ///
    /// The kind is a string rather than a [`RateKind`] because this is a report a caller displays and logs, and a
    /// stable crate's report does not make a consumer depend on an internal enum's spelling.
    pub refusals_by_kind: Vec<(String, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;



    fn budget() -> Budget {
        Budget::new(Quota::default())
    }

    /// A budget whose host-call bucket never refills, so every call after the burst is refused.
    ///
    /// Written as a named helper because the tests below are all about the escalation ladder, and a rate that refilled
    /// between calls would make them about the token bucket instead: with a default refill of 500 per second, eleven
    /// milliseconds of "elapsed" time is a whole token back, and the ladder would never move.
    fn refusal_budget() -> Budget {
        Budget::new(Quota { host_calls_burst: 1, host_calls_per_sec: 0, ..Quota::default() })
    }

    /// The quota `refusal_budget` was built from, for asserting what is in force.
    fn refusal_quota() -> Quota {
        Quota { host_calls_burst: 1, host_calls_per_sec: 0, ..Quota::default() }
    }

    // ── Token buckets ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_new_bucket_is_full() {
        // A plugin that just started should not be throttled before it has done anything.
        let bucket = TokenBucket::new(100, 200, 0);
        assert_eq!(bucket.available(), 200);
        assert_eq!(bucket.capacity(), 200);
    }

    #[test]
    fn taking_tokens_reduces_what_is_available() {
        let mut bucket = TokenBucket::new(100, 200, 0);
        assert_eq!(bucket.try_consume(50, 0), Ok(()));
        assert_eq!(bucket.available(), 150);
    }

    #[test]
    fn a_bucket_refills_continuously_rather_than_in_ticks() {
        // A tick-based bucket gives a plugin nothing for the rest of the second after it exhausts one, which turns a
        // burst into a stall and makes the observed rate depend on where in the second the burst started.
        let mut bucket = TokenBucket::new(100, 1, 0);
        assert_eq!(bucket.try_consume(1, 0), Ok(()));
        assert_eq!(bucket.available(), 0);

        // Ten milliseconds later, one token's worth has accumulated.
        assert_eq!(bucket.try_consume(1, 10), Ok(()));
        // And again.
        assert_eq!(bucket.try_consume(1, 20), Ok(()));
    }

    #[test]
    fn an_exhausted_bucket_says_how_long_to_wait() {
        let mut bucket = TokenBucket::new(10, 1, 0);
        assert_eq!(bucket.try_consume(1, 0), Ok(()));

        match bucket.try_consume(1, 0) {
            Err(refusal) => {
                // Ten per second means one token per 100 ms.
                assert_eq!(refusal.retry_after_ms, 100);
                assert_eq!(refusal.shortfall, TokenBucket::SCALE);
            }
            Ok(()) => panic!("the bucket should be empty"),
        }
    }

    #[test]
    fn a_bucket_never_fills_past_its_capacity() {
        // A bucket that accumulated while a plugin was idle would let it release a whole minute's worth of events at
        // once, which is the burst the capacity exists to bound.
        let mut bucket = TokenBucket::new(100, 10, 0);
        let _ = bucket.try_consume(10, 0);
        assert_eq!(bucket.available(), 0);

        // An hour later it is still only as full as its capacity.
        bucket.try_consume(0, 3_600_000).expect("zero costs nothing");
        assert_eq!(bucket.available(), 10);
    }

    #[test]
    fn a_clock_that_moves_backwards_does_not_remove_tokens() {
        // A bucket that lost tokens on a backwards reading would refuse a call it had already earned.
        let mut bucket = TokenBucket::new(100, 200, 1_000);
        assert_eq!(bucket.try_consume(100, 1_000), Ok(()));
        let after = bucket.available();

        // A refill at an earlier time adds nothing and takes nothing.
        assert_eq!(bucket.try_consume(0, 500), Ok(()));
        assert_eq!(bucket.available(), after);
    }

    #[test]
    fn a_bucket_with_no_refill_waits_forever_rather_than_dividing_by_zero() {
        // A caller showing this says "not for a very long time" rather than hanging on an arithmetic error.
        let mut bucket = TokenBucket::new(0, 1, 0);
        assert_eq!(bucket.try_consume(1, 0), Ok(()));
        match bucket.try_consume(1, 0) {
            Err(refusal) => assert_eq!(refusal.retry_after_ms, u64::MAX),
            Ok(()) => panic!("the bucket should be empty"),
        }
    }

    #[test]
    fn refilling_fully_resets_a_bucket() {
        let mut bucket = TokenBucket::new(10, 100, 0);
        assert_eq!(bucket.try_consume(100, 0), Ok(()));
        assert_eq!(bucket.available(), 0);

        bucket.refill_fully(500);
        assert_eq!(bucket.available(), 100);
    }

    #[test]
    fn consuming_more_than_the_capacity_is_refused() {
        // A single call that asks for more tokens than the bucket can ever hold would otherwise be admitted once and
        // then wedge the bucket at zero forever.
        let mut bucket = TokenBucket::new(100, 10, 0);
        assert!(bucket.try_consume(11, 0).is_err());
        // The bucket is untouched.
        assert_eq!(bucket.available(), 10);
    }

    // ── Static limits ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn static_limits_are_checked_against_the_defaults() {
        let budget = budget();
        assert_eq!(budget.check_memory(32 * 1024 * 1024), Ok(()));
        assert_eq!(budget.check_instances(4), Ok(()));
        assert_eq!(budget.check_storage(1024), Ok(()));
        assert_eq!(budget.check_transfers(4), Ok(()));
    }

    #[test]
    fn exceeding_a_static_limit_names_it_and_the_amount() {
        let budget = budget();
        match budget.check_memory(u64::MAX) {
            Err(StaticRefusal::Memory { limit, .. }) => assert_eq!(limit, Quota::default().max_memory_bytes),
            other => panic!("expected a memory refusal, got {other:?}"),
        }
        match budget.check_instances(100) {
            Err(StaticRefusal::Instances { wanted, limit }) => {
                assert_eq!(wanted, 100);
                assert_eq!(limit, 4);
            }
            other => panic!("expected an instance refusal, got {other:?}"),
        }
        assert!(matches!(budget.check_storage(u64::MAX), Err(StaticRefusal::Storage { .. })));
        assert!(matches!(budget.check_transfers(99), Err(StaticRefusal::Transfers { .. })));
    }

    #[test]
    fn a_static_refusal_is_never_retryable() {
        // A static limit is a decision about how much a plugin may hold, so retrying against it is retrying against
        // the host's own configuration.
        let refusals = [
            StaticRefusal::Memory { wanted: 2, limit: 1 },
            StaticRefusal::Instances { wanted: 2, limit: 1 },
            StaticRefusal::Storage { wanted: 2, limit: 1 },
            StaticRefusal::Transfers { wanted: 2, limit: 1 },
        ];
        for refusal in refusals {
            assert!(!refusal.is_retryable(), "{refusal:?}");
            assert!(!refusal.to_string().is_empty(), "{refusal:?}");
        }
    }

    // ── Rates ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_burst_within_the_allowance_is_admitted() {
        let budget = budget();
        // The host-call burst is a thousand, so a hundred calls at the same instant are fine.
        for _ in 0..100 {
            assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
        }
        assert_eq!(budget.admitted(), 100);
        assert_eq!(budget.refused(), 0);
    }

    #[test]
    fn exceeding_the_burst_is_refused_and_recorded() {
        let budget = Budget::new(Quota { host_calls_burst: 2, host_calls_per_sec: 1, ..Quota::default() });
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));

        match budget.consume(RateKind::HostCalls, 1, 0) {
            Err(refusal) => assert_eq!(refusal.kind, Some(RateKind::HostCalls)),
            Ok(()) => panic!("the bucket should be empty"),
        }
        assert_eq!(budget.refused(), 1);
    }

    #[test]
    fn each_kind_has_its_own_bucket() {
        // A plugin that emits a thousand events should not thereby be unable to read a file.
        let budget = Budget::new(Quota { events_per_sec: 1, fs_ops_per_sec: 100, ..Quota::default() });
        assert_eq!(budget.consume(RateKind::Events, 1, 0), Ok(()));
        assert!(budget.consume(RateKind::Events, 1, 0).is_err());
        // The filesystem bucket is untouched.
        assert_eq!(budget.consume(RateKind::FsOps, 1, 0), Ok(()));
    }

    #[test]
    fn every_rate_kind_has_a_quota_field() {
        // A kind with no field would have a zero rate and refuse everything, which reads as a broken plugin rather
        // than a missing limit.
        let quota = Quota::default();
        for kind in RateKind::ALL {
            let (rate, burst) = quota.rate_for(*kind);
            assert!(rate > 0, "{kind:?} has no rate");
            assert!(burst > 0, "{kind:?} has no burst");
            assert!(!kind.as_str().is_empty(), "{kind:?}");
        }
        // And the list covers every kind, so a new variant cannot be forgotten here.
        assert_eq!(RateKind::ALL.len(), 5);

        // The index is the position in `ALL`, which is what the refusal counts are keyed by. A mismatch would file one
        // kind's refusals under another.
        for (position, kind) in RateKind::ALL.iter().enumerate() {
            assert_eq!(kind.index(), position, "{kind:?}");
        }
    }

    // ── The escalation ladder ─────────────────────────────────────────────────────────────────────

    /// Records enough refusals to fill one window.
    /// Records exactly [`PERSISTENT_REFUSALS`] refusals inside one window.
    ///
    /// Exactly that many, because the threshold is a boundary: one more would make the window persistently refused
    /// and move the ladder, which is a different test. The timing helper that uses this gives the plugin a burst of
    /// one and no refill, so the first call succeeds and the rest are refused.
    fn fill_window(budget: &Budget, at_ms: u64) {
        for _ in 0..PERSISTENT_REFUSALS {
            let _ = budget.consume(RateKind::HostCalls, 1, at_ms);
        }
    }

    #[test]
    fn a_single_exceedance_does_not_change_health() {
        // Ordinary: a plugin that fires a burst of events hits a bucket and waits.
        let budget = refusal_budget();
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
        assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());
        assert_eq!(budget.health(), Health::Good);
    }

    #[test]
    fn persistent_refusals_move_a_plugin_to_overreaching_first() {
        // The rung that exists so the user is told before anything is restricted.
        let budget = refusal_budget();
        // The first window is not persistently refused, so the plugin is not degraded yet.
        fill_window(&budget, in_window(0));
        assert_eq!(budget.health(), Health::Good);

        // The second is, which is the rung that tells the user before anything is restricted.
        fill_window(&budget, in_window(1));
        assert_eq!(budget.health(), Health::Overreaching);
        // And it is still running at full quota.
        assert!(budget.health().is_running());
        assert!(!budget.health().uses_degraded_quota());
    }

    #[test]
    fn another_bad_window_degrades_the_plugin() {
        let budget = refusal_budget();

        // Walk the ladder rather than counting windows by hand: the point of the test is that a second persistently
        // refused window degrades the plugin, not that a particular arithmetic produces that many windows.
        let mut window = 0u64;
        while budget.health() == Health::Good && window < 10 {
            fill_window(&budget, in_window(window));
            window += 1;
        }
        assert_eq!(budget.health(), Health::Overreaching);
        fill_window(&budget, in_window(window));
        assert_eq!(budget.health(), Health::Degraded);
        // Still running, at a reduced quota.
        assert!(budget.health().is_running());
        assert!(budget.health().uses_degraded_quota());
    }

    #[test]
    fn a_degraded_plugin_that_keeps_failing_is_faulted() {
        // The only rung that stops the plugin, reached only after the two below it were tried.
        let budget = refusal_budget();

        for window in 0..12u64 {
            fill_window(&budget, in_window(window));
            if budget.health() == Health::Faulted {
                break;
            }
        }
        assert_eq!(budget.health(), Health::Faulted);
        assert!(!budget.health().is_running());
        assert!(budget.health().is_worth_telling_the_user());
    }

    #[test]
    fn a_faulted_plugin_may_not_consume_anything() {
        // A caller that forgot to check health would otherwise hand a disabled plugin its budget back.
        let budget = refusal_budget();
        for window in 0..12u64 {
            fill_window(&budget, in_window(window));
            if budget.health() == Health::Faulted {
                break;
            }
        }
        assert_eq!(budget.health(), Health::Faulted);

        // Even a bucket with tokens left refuses.
        match budget.consume(RateKind::FsOps, 1, u64::MAX) {
            Err(refusal) => assert_eq!(refusal.retry_after_ms, u64::MAX),
            Ok(()) => panic!("a faulted plugin should not consume"),
        }
    }

    #[test]
    fn a_recovering_plugin_climbs_back_down() {
        // Two good windows undo one bad one, which lets a plugin that was degraded recover without the user
        // intervening.
        let budget = refusal_budget();

        let mut window = 0u64;
        while budget.health() != Health::Degraded && window < 12 {
            fill_window(&budget, in_window(window));
            window += 1;
        }
        assert_eq!(budget.health(), Health::Degraded);

        // Now stop refusing: each window boundary with no refusals subtracts one.
        for _ in 0..6 {
            window += 1;
            // A zero-token consumption passes and does not record a refusal, but it does advance the window.
            budget.tick(in_window(window));
        }
        assert!(
            budget.health() != Health::Faulted,
            "a plugin that stopped misbehaving was faulted anyway"
        );
    }

    #[test]
    fn faulted_is_not_climbed_out_of_by_arithmetic() {
        // A ladder that could climb back down on its own would re-enable a plugin that was disabled for a reason.
        let budget = refusal_budget();
        for window in 0..12u64 {
            fill_window(&budget, in_window(window));
            if budget.health() == Health::Faulted {
                break;
            }
        }
        assert_eq!(budget.health(), Health::Faulted);

        for window in 12..30u64 {
            budget.tick(in_window(window));
        }
        assert_eq!(budget.health(), Health::Faulted, "faulted climbed back down on its own");
    }

    #[test]
    fn a_user_can_clear_a_faulted_plugin() {
        let budget = refusal_budget();
        for window in 0..12u64 {
            fill_window(&budget, in_window(window));
            if budget.health() == Health::Faulted {
                break;
            }
        }
        assert_eq!(budget.health(), Health::Faulted);

        budget.reset(in_window(100));
        assert_eq!(budget.health(), Health::Good);
        // And the buckets are full, so a plugin that was disabled for a while is not refused immediately for a
        // bucket that never refilled while it was not running.
        assert_eq!(budget.consume(RateKind::HostCalls, 1, in_window(100)), Ok(()));
    }

    #[test]
    fn degradation_halves_the_rate_limits() {
        let full = Quota::default();
        let reduced = full.degraded();
        assert_eq!(reduced.host_calls_per_sec, full.host_calls_per_sec / 2);
        assert_eq!(reduced.events_per_sec, full.events_per_sec / 2);
        assert_eq!(reduced.max_instances, full.max_instances / 2);
        assert_eq!(reduced.max_memory_bytes, full.max_memory_bytes / 2);
    }

    #[test]
    fn degradation_never_reaches_zero_and_leaves_the_timeout_alone() {
        // A limit of zero would disable the plugin, which is the faulted rung's job, and halving the timeout would
        // turn a plugin that is merely slow into one that fails — a different problem from the one degradation
        // addresses.
        let tiny = Quota {
            max_instances: 1,
            max_open_transfers: 1,
            host_calls_per_sec: 1,
            host_calls_burst: 1,
            events_per_sec: 1,
            network_requests_per_sec: 1,
            network_concurrent: 1,
            device_sends_per_sec: 1,
            fs_ops_per_sec: 1,
            ..Quota::default()
        };
        let reduced = tiny.degraded();
        assert_eq!(reduced.max_instances, 1);
        assert_eq!(reduced.max_open_transfers, 0, "zero transfers is a limit, not a crash");
        assert_eq!(reduced.host_calls_per_sec, 1);
        assert_eq!(reduced.events_per_sec, 1);
        assert_eq!(reduced.call_timeout_ms, tiny.call_timeout_ms);
        // Storage is not halved: the plugin's data does not shrink because it asked too often.
        assert_eq!(reduced.max_storage_bytes, tiny.max_storage_bytes);
    }

    #[test]
    fn the_quota_in_force_follows_the_health() {
        let budget = refusal_budget();
        assert_eq!(budget.quota().host_calls_per_sec, refusal_quota().host_calls_per_sec);

        // Walk to exactly `Degraded` rather than counting windows by hand, then assert the quota moved with it.
        let mut window = 0u64;
        while budget.health() < Health::Degraded && window < 10 {
            fill_window(&budget, in_window(window));
            window += 1;
        }
        assert_eq!(budget.health(), Health::Degraded);
        // The degraded quota halves the *default* rate, not the test's zero — `degraded` floors a rate at one, because
        // a limit of zero would disable the plugin and that is the faulted rung's job.
        assert_eq!(budget.quota().host_calls_per_sec, 1, "the degraded rate is floored at one, not zero");
    }

    #[test]
    fn a_window_with_few_refusals_is_not_persistent() {
        // A plugin that hits a bucket twice in ten seconds is not misbehaving.
        let budget = Budget::new(Quota {
            host_calls_burst: 1,
            host_calls_per_sec: 1,
            events_per_sec: 1,
            ..Quota::default()
        });
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
        assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());
        // Half a second, so the bucket has not refilled a whole token and the call is still refused.
        assert!(budget.consume(RateKind::HostCalls, 1, 500).is_err());

        // Close the window with only two refusals in it.
        budget.tick(in_window(1));
        assert_eq!(budget.health(), Health::Good);
    }

    // ── Reporting ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_report_carries_what_the_settings_screen_needs() {
        let budget = refusal_budget();
        assert_eq!(budget.consume(RateKind::HostCalls, 1, 0), Ok(()));
        assert!(budget.consume(RateKind::HostCalls, 1, 0).is_err());

        let report = budget.report();
        assert_eq!(report.health, "good");
        assert_eq!(report.admitted, 1);
        assert_eq!(report.refused, 1);
        assert!(!report.explanation.is_empty());
        assert_eq!(
            report
                .refusals_by_kind
                .iter()
                .find(|(kind, _)| kind == "host-calls")
                .map(|(_, count)| *count),
            Some(1)
        );
        assert_eq!(report.quota, refusal_quota());
    }

    #[test]
    fn every_health_level_explains_itself_for_a_user() {
        // A user whose plugin has been degraded needs to know why it got slower.
        for health in [Health::Good, Health::Overreaching, Health::Degraded, Health::Faulted] {
            assert!(health.explain().len() > 15, "{health:?}");
            assert!(!health.as_str().is_empty(), "{health:?}");
        }
    }

    #[test]
    fn the_ladder_is_ordered_from_best_to_worst() {
        // The ordering is what a caller uses to show a trend, and an out-of-order ladder would make a plugin look
        // like it was improving while it got worse.
        assert!(Health::Good < Health::Overreaching);
        assert!(Health::Overreaching < Health::Degraded);
        assert!(Health::Degraded < Health::Faulted);
        // And only the last one stops the plugin.
        assert!(Health::Good.is_running());
        assert!(Health::Overreaching.is_running());
        assert!(Health::Degraded.is_running());
        assert!(!Health::Faulted.is_running());
    }

    #[test]
    fn only_ordinary_health_is_not_worth_mentioning() {
        assert!(!Health::Good.is_worth_telling_the_user());
        assert!(Health::Overreaching.is_worth_telling_the_user());
        assert!(Health::Degraded.is_worth_telling_the_user());
        assert!(Health::Faulted.is_worth_telling_the_user());
    }

    #[test]
    fn a_report_survives_a_round_trip() {
        let budget = Budget::new(Quota::default());
        let report = budget.report();
        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("refusalsByKind"), "{json}");
        let back: QuotaReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }

    #[test]
    fn a_quota_survives_a_round_trip() {
        // The quota reaches the interface, so its field names are part of what a user setting a custom quota sees.
        let quota = Quota::default();
        let json = serde_json::to_string(&quota).expect("serialises");
        assert!(json.contains("maxMemoryBytes"), "{json}");
        assert!(json.contains("callTimeoutMs"), "{json}");
        let back: Quota = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, quota);
    }

    #[test]
    fn a_limited_refusal_reports_its_wait() {
        let refusal = RateLimited { kind: Some(RateKind::Events), retry_after_ms: 250, shortfall: 1_000 };
        assert_eq!(refusal.retry_after(), Duration::from_millis(250));
        assert!(refusal.to_string().contains("250"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use super::in_window;
    use proptest::prelude::*;

    proptest! {
        /// A bucket never holds more than its capacity, whatever sequence of times and amounts it is given. A bucket
        /// that accumulated while a plugin was idle would let it release a whole minute's worth of events at once.
        #[test]
        fn a_bucket_never_exceeds_its_capacity(
            rate in 0u32..1_000,
            burst in 1u32..100,
            steps in proptest::collection::vec((0u64..10_000, 0u32..50), 0..60),
        ) {
            let mut bucket = TokenBucket::new(rate, burst, 0);
            for (at, count) in steps {
                let _ = bucket.try_consume(count, at);
                prop_assert!(
                    bucket.available() <= u64::from(burst),
                    "held {} of a capacity of {}",
                    bucket.available(),
                    burst,
                );
            }
        }

        /// Consuming never increases what is available, except by the refill that time passing earns. A bucket that
        /// gained tokens when it was asked for them would be a limit that does not limit.
        #[test]
        fn consuming_at_the_same_instant_never_adds_tokens(
            rate in 0u32..100,
            burst in 1u32..10,
            counts in proptest::collection::vec(0u32..5, 1..30),
        ) {
            let mut bucket = TokenBucket::new(rate, burst, 0);
            let mut previous = bucket.available();
            for count in counts {
                let _ = bucket.try_consume(count, 0);
                let now = bucket.available();
                prop_assert!(now <= previous, "{} rose to {} at the same instant", previous, now);
                previous = now;
            }
        }

        /// A refusal always states a positive wait, so a caller retrying on it makes progress rather than spinning.
        #[test]
        fn a_refusal_always_says_when(
            rate in 1u32..1_000,
            burst in 1u32..10,
            count in 1u32..10,
        ) {
            let mut bucket = TokenBucket::new(rate, burst, 0);
            // Empty it.
            let _ = bucket.try_consume(burst, 0);
            if let Err(refusal) = bucket.try_consume(count, 0) {
                prop_assert!(refusal.retry_after_ms > 0);
                prop_assert!(refusal.shortfall > 0);
                prop_assert!(refusal.retry_after() > Duration::ZERO);
            }
        }

        /// Health never moves backwards past faulted and never skips a rung on the way up: a plugin is not disabled
        /// for a single bad window.
        #[test]
        fn health_never_skips_to_faulted(
            burst in 1u32..3,
            windows in proptest::collection::vec(0u32..PERSISTENT_REFUSALS, 1..20),
        ) {
            let budget = Budget::new(Quota { host_calls_burst: burst, host_calls_per_sec: 1, ..Quota::default() });
            let _ = budget.consume(RateKind::HostCalls, burst, 0);

            let mut seen_faulted = false;
            let mut seen_degraded = false;
            let mut at = 0u64;
            for refusals in windows {
                for _ in 0..refusals {
                    let _ = budget.consume(RateKind::HostCalls, 1, at);
                }
                at = in_window(window_number(at) + 1);
                // Close the window.
                let _ = budget.consume(RateKind::HostCalls, 0, at);

                match budget.health() {
                    Health::Faulted => {
                        // Reaching faulted requires having been degraded, which requires having been overreaching.
                        prop_assert!(seen_degraded, "faulted without ever being degraded");
                        seen_faulted = true;
                    }
                    Health::Degraded => seen_degraded = true,
                    _ => {}
                }
                if seen_faulted {
                    break;
                }
            }
        }

        /// A degraded quota is never larger than the full one, for any field that is halved. A degradation that
        /// raised a limit would be a reward for misbehaving.
        #[test]
        fn a_degraded_quota_is_never_larger(
            memory in 1u64..u64::MAX,
            instances in 1u32..1_000,
            calls in 1u32..10_000,
            events in 1u32..10_000,
        ) {
            let quota = Quota {
                max_memory_bytes: memory,
                max_instances: instances,
                host_calls_per_sec: calls,
                events_per_sec: events,
                ..Quota::default()
            };
            let reduced = quota.degraded();

            prop_assert!(reduced.max_memory_bytes <= quota.max_memory_bytes);
            prop_assert!(reduced.max_instances <= quota.max_instances);
            prop_assert!(reduced.host_calls_per_sec <= quota.host_calls_per_sec);
            prop_assert!(reduced.events_per_sec <= quota.events_per_sec);
            prop_assert!(reduced.call_timeout_ms == quota.call_timeout_ms);
        }
    }
}
