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
            //
            // ★ Counted as well as returned from, because "this machine has no discovery socket" is a state a user asks
            // about — and a `return` that only ever appears in the daemon's own log is invisible to `status`.
            self.count_scan("unavailable");
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

        // ★ And what the scan heard, which is the question the design's discovery group exists for.
        //
        // "Scanned and found nothing" and "scanned and found three" are two different situations for a user reading
        // `devices`, and only one of them is a problem. A count that is never recorded makes them the same.
        self.count_scan("ran");
        let found = u64::try_from(self.host.lock().discovery().len()).unwrap_or(u64::MAX);
        self.metrics.histogram_observe(
            &synra_observe::metrics::SeriesKey::new("candidates_found", Vec::new()),
            found as f64,
        );
        self.metrics.histogram_observe(
            &synra_observe::metrics::SeriesKey::new("scan_duration_ms", Vec::new()),
            started.elapsed().as_secs_f64() * 1_000.0,
        );
    }

    /// Counts one scan by how it ended.
    fn count_scan(&self, result: &str) {
        self.metrics
            .counter_inc(&synra_observe::metrics::SeriesKey::new(
                "scans_total",
                [("result".to_owned(), result.to_owned())],
            ));
    }
}
