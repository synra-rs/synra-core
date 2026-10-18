//! A bound on how many control connections the daemon serves at once.
//!
//! # Why a bound exists at all
//!
//! The control socket is local, and the design treats it as inside the trust boundary — but "trusted" is not "bounded".
//! A client with a bug can open connections in a loop, and every one of them costs a thread and a stack until the process
//! runs out. The bound is not a security boundary; it is the difference between a busy kernel and a kernel that cannot
//! accept the next real command.
//!
//! # What happens at the bound
//!
//! The connection is accepted and closed. Sending a refusal would need a request to answer, and a client that is over the
//! limit is not one whose request is worth reading; closing is the answer that costs nothing and is impossible to
//! misunderstand. The caller sees a transport error naming the closed connection, which is the truth.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The most control connections served at once.
///
/// Sixty-four is far past the number of commands a desktop's interface and a person's shell open together, and small
/// enough that a leak is visible in the process's thread count rather than in a failed allocation.
pub(crate) const MAX_CONTROL_CONNECTIONS: usize = 64;

/// Counts the control connections currently being served.
pub(crate) struct ControlGate {
    active: AtomicUsize,
    max: usize,
    /// Where the current count is reported, when a recorder is available.
    ///
    /// ★ A gauge rather than an incrementing counter: the question `status` answers is "how many are open **now**", and a
    /// counter would only say how many ever opened. It is updated on both edges — admission and the permit's drop — so a
    /// reader cannot see a count that lags the threads.
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
    /// Guards the wait for "all connections have finished".
    idle: parking_lot::Mutex<()>,
    /// Signalled whenever a connection ends, so shutdown can wait without polling.
    idle_changed: parking_lot::Condvar,
}

impl ControlGate {
    /// A gate that admits at most `max` connections at once.
    #[must_use]
    pub(crate) const fn new(max: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max,
            metrics: None,
            idle: parking_lot::Mutex::new(()),
            idle_changed: parking_lot::Condvar::new(),
        }
    }

    /// Reports the current count to a recorder.
    #[must_use]
    pub(crate) fn with_metrics(mut self, metrics: Arc<synra_observe::metrics::RingRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Writes the current count to the recorder, when there is one.
    fn publish(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.gauge_set(
                &synra_observe::metrics::SeriesKey::new("control_connections", Vec::new()),
                i64::try_from(self.active.load(Ordering::Relaxed)).unwrap_or(i64::MAX),
            );
        }
    }

    /// Admits one connection, or refuses when the gate is full.
    ///
    /// The returned [`Permit`] gives the slot back when it is dropped, so the count cannot leak on a connection whose
    /// thread returns early or panics.
    #[must_use]
    pub(crate) fn try_enter(self: &Arc<Self>) -> Option<Permit> {
        let mut current = self.active.load(Ordering::Relaxed);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.publish();
                    return Some(Permit { gate: Arc::clone(self) });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// How many connections are being served right now.
    #[must_use]
    pub(crate) fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Waits until every admitted connection has finished, or the timeout expires.
    ///
    /// # Why shutdown waits at all
    ///
    /// Because the process is about to drop the database and the runtime those connections use, and a command that is
    /// halfway through a query would be reading freed state. Waiting is bounded rather than unconditional: a client that
    /// holds a connection open for ever must not make the daemon unkillable, so after the grace period the process goes on
    /// and says what was still open.
    pub(crate) fn wait_for_idle(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        // The lock is held across the counter check and the wait, so a connection that finishes between them cannot be
        // missed: its drop must take the same lock before it notifies.
        let mut guard = self.idle.lock();
        while self.active.load(Ordering::Relaxed) > 0 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            if self.idle_changed.wait_for(&mut guard, left).timed_out()
                && self.active.load(Ordering::Relaxed) > 0
            {
                return false;
            }
        }
        true
    }
}

/// One admitted connection; dropping it frees the slot.
pub(crate) struct Permit {
    gate: Arc<ControlGate>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        // ★ The decrement and the notification happen under the same lock `wait_for_idle` holds, so a waiter cannot check
        // the count, decide it is non-zero, and then sleep through the notification that made it zero.
        {
            let _guard = self.gate.idle.lock();
            self.gate.active.fetch_sub(1, Ordering::AcqRel);
            self.gate.idle_changed.notify_all();
        }
        self.gate.publish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_admits_up_to_its_bound_and_no_further() {
        let gate = Arc::new(ControlGate::new(2));
        let first = gate.try_enter().expect("one");
        let second = gate.try_enter().expect("two");
        assert!(gate.try_enter().is_none(), "a third connection was admitted");
        assert_eq!(gate.active(), 2);

        drop(first);
        assert_eq!(gate.active(), 1);
        let third = gate.try_enter().expect("a freed slot is reusable");
        assert_eq!(gate.active(), 2);
        drop(second);
        drop(third);
        assert_eq!(gate.active(), 0, "every permit returned its slot");
    }

    #[test]
    fn the_gate_reports_its_count_as_a_gauge() {
        // ★ The gauge is what `status` shows, and a gauge that was only incremented on admission would grow for ever.
        let metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
        let gate = Arc::new(ControlGate::new(2).with_metrics(Arc::clone(&metrics)));

        let first = gate.try_enter().expect("one");
        assert_eq!(
            metrics.snapshot().get("control_connections"),
            Some(&synra_observe::metrics::Value::Gauge(1))
        );
        let second = gate.try_enter().expect("two");
        assert_eq!(
            metrics.snapshot().get("control_connections"),
            Some(&synra_observe::metrics::Value::Gauge(2))
        );
        drop(first);
        assert_eq!(
            metrics.snapshot().get("control_connections"),
            Some(&synra_observe::metrics::Value::Gauge(1)),
            "the gauge must follow the connections down as well as up"
        );
        drop(second);
        assert_eq!(
            metrics.snapshot().get("control_connections"),
            Some(&synra_observe::metrics::Value::Gauge(0))
        );
    }

    #[test]
    fn a_gate_reports_when_its_last_connection_leaves() {
        // ★ Shutdown waits on this. The short timeout is the property, not a sleep: a gate with a connection still open
        // must answer "no" rather than block.
        let gate = Arc::new(ControlGate::new(2));
        let held = gate.try_enter().expect("one");
        assert!(!gate.wait_for_idle(std::time::Duration::from_millis(1)));
        drop(held);
        assert!(gate.wait_for_idle(std::time::Duration::from_millis(1)));
    }

    #[test]
    fn a_gate_of_one_refuses_the_second_client() {
        let gate = Arc::new(ControlGate::new(1));
        let _held = gate.try_enter().expect("the single slot");
        assert!(gate.try_enter().is_none());
    }
}
