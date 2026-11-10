use core::time::Duration;

use super::Liveness;

mod health;
mod heartbeat;

/// A tracker with timings small enough to reason about: 100 ms interval, 250 ms timeout.
pub(super) fn tracker(now_ms: u64) -> Liveness {
    Liveness::new(now_ms).with_timing(Duration::from_millis(100), Duration::from_millis(250))
}
