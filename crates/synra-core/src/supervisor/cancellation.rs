//! Cancellation wakes every waiter without polling or losing a notification.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

/// A shared stop request, readable without locking and able to interrupt a wait.
#[derive(Debug, Clone, Default)]
pub struct Cancellation {
    state: Arc<State>,
}

#[derive(Debug, Default)]
struct State {
    cancelled: AtomicBool,
    waiting: Mutex<()>,
    changed: Condvar,
}

impl Cancellation {
    /// A token that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests a stop and wakes all threads waiting on this token or its clones.
    pub fn cancel(&self) {
        // The same mutex protects the predicate check and the transition into sleep. Without it, cancellation between
        // those operations could notify before the thread waits and leave it asleep until its timeout.
        let _waiting = self.state.waiting.lock();
        self.state.cancelled.store(true, Ordering::Release);
        self.state.changed.notify_all();
    }

    /// Whether a stop has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Waits until cancellation or the timeout, returning whether a stop was requested.
    ///
    /// Long waits consume no polling wakeups. Spurious notifications keep waiting against the original timeout.
    #[must_use]
    pub fn wait(&self, timeout: Duration) -> bool {
        let mut waiting = self.state.waiting.lock();
        self.state
            .changed
            .wait_while_for(&mut waiting, |_| !self.is_cancelled(), timeout);
        drop(waiting);
        self.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn cancellation_wakes_every_clone_waiting_for_a_long_time() {
        let cancel = Cancellation::new();
        let (ready, ready_rx) = mpsc::channel();
        let (done, done_rx) = mpsc::channel();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let token = cancel.clone();
                let ready = ready.clone();
                let done = done.clone();
                std::thread::spawn(move || {
                    ready.send(()).expect("ready");
                    let stopped = token.wait(Duration::from_secs(5));
                    done.send(stopped).expect("result");
                })
            })
            .collect();
        for _ in 0..4 {
            ready_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("worker ready");
        }
        cancel.cancel();
        for _ in 0..4 {
            assert!(
                done_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("cancellation wakes worker")
            );
        }
        for worker in threads {
            worker.join().expect("worker exits");
        }
    }

    #[test]
    fn cancellation_before_waiting_is_not_lost() {
        let cancel = Cancellation::new();
        cancel.cancel();
        cancel.cancel();
        assert!(cancel.wait(Duration::ZERO));
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn an_expired_wait_does_not_cancel_the_token() {
        let cancel = Cancellation::new();
        assert!(!cancel.wait(Duration::ZERO));
        assert!(!cancel.wait(Duration::from_millis(1)));
        assert!(!cancel.is_cancelled());
    }
}
