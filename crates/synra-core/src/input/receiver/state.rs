use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use synra_platform::pointer::Factory;
use synra_protocol::ids::SessionId;

use super::super::LEASE;
use super::{Phase, Policy, Receiver, Snapshot};

impl Receiver {
    /// Build a receiver with durable policy, OS factory and host UI notification.
    pub fn new(
        policy: Arc<dyn Policy>,
        factory: Arc<Factory>,
        notify: Arc<dyn Fn(Option<Snapshot>) + Send + Sync>,
    ) -> Self {
        Self {
            policy,
            factory,
            state: Mutex::new(None),
            pointer_lease: Mutex::new(()),
            publication: Mutex::new(None),
            stopping: AtomicBool::new(false),
            notify,
        }
    }

    /// Current request or last terminal state, without holding the guard during publication.
    #[must_use]
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.state.lock().clone()
    }

    /// Accept/refuse exactly the pending session the UI displayed.
    pub fn decide(&self, id: SessionId, allow: bool) -> bool {
        let changed = {
            let mut state = self.state.lock();
            if let Some(current) = state
                .as_mut()
                .filter(|s| s.session == id && s.phase == Phase::Pending)
            {
                current.phase = if allow { Phase::Allowed } else { Phase::Ended };
                current.reason = (!allow).then(|| "declined".to_owned());
                true
            } else {
                false
            }
        };
        if changed {
            self.publish();
        }
        changed
    }

    /// Revoke a pending or active session. The link thread releases within its 100ms poll bound.
    pub fn stop(&self, id: SessionId) {
        self.finish(id, "stopped");
    }

    /// End input before a deliberate host exit and wait, with a bound, for native button release.
    /// Returns false only if the native worker did not relinquish the pointer in time.
    #[must_use]
    pub fn shutdown(&self) -> bool {
        self.stopping.store(true, Ordering::Release);
        if let Some(snapshot) = self.snapshot() {
            self.finish(snapshot.session, "host stopped");
        }
        self.pointer_lease.try_lock_for(LEASE + LEASE).is_some()
    }

    pub(in crate::input::receiver) fn finish(&self, id: SessionId, reason: &str) {
        let changed = {
            let mut state = self.state.lock();
            if let Some(current) = state
                .as_mut()
                .filter(|s| s.session == id && s.phase != Phase::Ended)
            {
                current.phase = Phase::Ended;
                current.reason = Some(reason.to_owned());
                true
            } else {
                false
            }
        };
        if changed {
            self.publish();
        }
    }

    pub(in crate::input::receiver) fn phase(&self, id: SessionId) -> Phase {
        self.state
            .lock()
            .as_ref()
            .filter(|s| s.session == id)
            .map_or(Phase::Ended, |s| s.phase)
    }

    pub(in crate::input::receiver) fn publish(&self) {
        // Decisions and link progress occur on different threads. Read the newest state
        // after acquiring publication ownership so a late Pending cannot replace Active.
        let mut publication = self.publication.lock();
        let snapshot = self.snapshot();
        if *publication == snapshot {
            return;
        }
        *publication = snapshot.clone();
        (self.notify)(snapshot);
        drop(publication);
    }
}
