//! The budget itself, the health it reaches, and the report it produces.

use serde::{Deserialize, Serialize};

use super::ledger::{RateLimited, StaticRefusal, TokenBucket};
use super::limits::{Quota, RateKind};

mod health;

pub use health::{
    DEGRADE_AFTER_WINDOWS, FAULT_AFTER_WINDOWS, Health, PERSISTENCE_WINDOW, PERSISTENT_REFUSALS,
    window_number,
};
#[cfg(test)]
pub(crate) use health::in_window;

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
