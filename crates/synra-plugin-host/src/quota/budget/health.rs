//! The persistence windows and the transitions they drive.

use core::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Budget, RateKind};

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

impl Budget {
    /// Records a refusal.
    ///
    /// The window is derived from the timestamp rather than kept as state. Two plugins that are refused at the same
    /// instant are in the same window whatever order their calls arrive in, so the ladder does not depend on when
    /// each plugin's budget happened to be created — and a window cannot be closed early by an unrelated call.
    pub(super) fn record_refusal(&self, kind: RateKind, now_ms: u64) {
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
}
