use super::{Runtime, now_ms};

impl Runtime {
    /// Asks the discovery worker to scan for a while, and waits for it.
    ///
    /// # Why the deadline is published rather than the work being done here
    ///
    /// Because the worker owns the sockets. This sets the deadline the worker reads and then waits, polling the table —
    /// which is the only thing it can do, since the worker is a separate thread and there is no channel between them.
    /// The wait is bounded by the request, and the deadline expires on its own if this caller goes away.
    pub(super) fn scan(&self, scan_ms: u64) {
        let Some(discovery) = &self.discovery else {
            // Nothing to scan with. Reported once rather than as a failure: the answer is still the table, which is all
            // a kernel without a discovery socket can honestly offer.
            return;
        };

        // The protocol's scan budget is the ceiling: a client may not ask the kernel to broadcast for longer than one
        // scan is allowed to run, because the request is unauthenticated input from a local process.
        let budget = scan_ms.min(u64::try_from(synra_protocol::limits::SCAN_TOTAL.as_millis()).unwrap_or(u64::MAX));
        let deadline = now_ms().saturating_add(budget);
        self.scan_until_ms
            .store(synra_core::millis_reading(deadline), std::sync::atomic::Ordering::Relaxed);

        // The wait is on the clock rather than on the table, because a table that stopped changing is not the signal —
        // the signal is the budget running out. Discovery's own scan window is what the protocol specifies.
        let started = std::time::Instant::now();
        let window = synra_protocol::limits::SCAN_PASSIVE.min(std::time::Duration::from_millis(budget));
        while started.elapsed() < window {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // Released here rather than left to expire, so a scan does not keep broadcasting for the remainder of its
        // deadline after the client has been answered. The worker's own check would catch it, but only within one tick.
        let _ = discovery;
        self.scan_until_ms.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}
