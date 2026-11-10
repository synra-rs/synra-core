//! Rate and hourly limits for notifications and input.

use crate::actions::{PlatformAction, Policies};
use crate::error::PlatformError;

const NOTIFICATION_WINDOW_MS: u64 = 3_600_000;

/// Decides whether an action may proceed, given how it has been used.
///
/// A rate limiter rather than a scheduler: it answers "may this happen now" and records the answer, and the
/// caller supplies the clock. Keeping the clock out means the limits can be tested without sleeping.
#[derive(Debug)]
pub struct RateLimiter {
    policies: Policies,
    /// The last time each rate-limited action ran.
    last: parking_lot::Mutex<std::collections::HashMap<PlatformAction, u64>>,
    /// A sliding window of notification times, for the hourly ceiling.
    notifications: parking_lot::Mutex<Vec<u64>>,
}

impl RateLimiter {
    /// A limiter with the given policies.
    #[must_use]
    pub fn new(policies: Policies) -> Self {
        Self {
            policies,
            last: parking_lot::Mutex::new(std::collections::HashMap::new()),
            notifications: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// The policies in force.
    #[must_use]
    pub const fn policies(&self) -> &Policies {
        &self.policies
    }

    /// Checks an action and records it, at `now_ms`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::RateLimited`] or [`PlatformError::QuotaExceeded`].
    pub fn admit(&self, action: PlatformAction, now_ms: u64) -> Result<(), PlatformError> {
        let interval = match action {
            PlatformAction::SimulateKeys => self.policies.key_chord_interval,
            PlatformAction::Notify => self.policies.notification_interval,
            // Everything else is bounded by the action's own cost or by a capability the user granted once; a
            // rate limit on `open-url` would refuse a legitimate burst of links a user clicked.
            _ => return Ok(()),
        };
        let interval_ms = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);

        if action == PlatformAction::Notify {
            let mut times = self.notifications.lock();
            // The window is one hour, and entries older than that are dropped rather than counted: a fixed
            // window would let a plugin fire the whole ceiling at the end of one hour and again at the start of
            // the next.
            times.retain(|at| now_ms.saturating_sub(*at) < NOTIFICATION_WINDOW_MS);
            let limit = self.policies.notifications_per_hour;
            if times.len() >= limit as usize {
                return Err(PlatformError::QuotaExceeded {
                    action,
                    used: u32::try_from(times.len()).unwrap_or(u32::MAX),
                    limit,
                });
            }
            times.push(now_ms);
        }

        // The decision is made inside a block so the guard is released before the `return`. Holding a lock across
        // an early return is a borrowed-scrutinee that `clippy::correctness` refuses, and the fix is the code's
        // shape rather than an annotation: the lock's job is to read one entry, not to span the rest of the
        // function.
        {
            let mut last = self.last.lock();
            let outcome = match last.get(&action) {
                Some(previous) => {
                    let elapsed = now_ms.saturating_sub(*previous);
                    if elapsed < interval_ms {
                        Err(PlatformError::RateLimited {
                            action,
                            remaining_ms: interval_ms - elapsed,
                        })
                    }
                    else {
                        Ok(())
                    }
                }
                None => Ok(()),
            };
            if outcome.is_ok() {
                last.insert(action, now_ms);
            }
            outcome
        }
    }

    /// Forgets a rate-limited action's history.
    ///
    /// For a test, and for a caller that knows the clock jumped — a device resuming from suspend has a
    /// monotonic clock that did not advance, and the alternative to forgetting is a plugin that cannot notify
    /// until the process restarts.
    pub fn forget(&self, action: PlatformAction) {
        self.last.lock().remove(&action);
        if action == PlatformAction::Notify {
            self.notifications.lock().clear();
        }
    }

    /// How many notifications were recorded inside the window ending at `now_ms`.
    #[must_use]
    pub fn notifications_in_window(&self, now_ms: u64) -> u32 {
        let mut times = self.notifications.lock();
        times.retain(|at| now_ms.saturating_sub(*at) < NOTIFICATION_WINDOW_MS);
        u32::try_from(times.len()).unwrap_or(u32::MAX)
    }
}
