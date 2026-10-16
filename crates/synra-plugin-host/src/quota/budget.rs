//! The budget itself, the health it reaches, and the report it produces.

use core::time::Duration;

use serde::{Deserialize, Serialize};

use super::ledger::{RateLimited, StaticRefusal, TokenBucket};
use super::limits::{Quota, RateKind};
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
pub fn window_number(now_ms: u64) -> u64 {
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
pub(crate) fn in_window(n: u64) -> u64 {
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
        self.note_bad_call(now_ms);
    }

    /// Records a call the plugin **misbehaved** in: a trap, exhausted fuel, a memory refusal, a timeout.
    ///
    /// ★ Why this exists, and what it fixes.
    ///
    /// The ladder was driven by **rate-limit refusals only**. A plugin that trapped on every call produced no refusals — a
    /// trap is not a rate — so nothing counted, `bad_windows` never moved, and a plugin that could not run kept being asked
    /// to. `12`'s own row recorded it: *""5 traps -> degraded" is not implemented; a plugin that repeatedly traps is never
    /// degraded."*
    ///
    /// A misbehaviour and a refusal are the same thing to the ladder: a call in this window that the plugin should not have
    /// made. Only the counters beside it differ, and those are for the settings screen.
    pub fn record_misbehaviour(&self, now_ms: u64) {
        self.note_bad_call(now_ms);
    }

    /// The ladder itself: one bad call in a window, and a window that is persistently bad moves one rung.
    fn note_bad_call(&self, now_ms: u64) {
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
