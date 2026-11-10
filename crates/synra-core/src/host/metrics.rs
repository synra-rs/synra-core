use super::kernel::Host;

impl Host {
    /// Counts one frame this host sent, by event.
    ///
    /// ★ Since 2026-10-19 the frame counters live on `PeerLink`, which records every frame — including the offer and
    /// pairing frames a dialled link writes outside this host. `Host::send` therefore does **not** call this, and a caller
    /// that did would double the frame; it remains for a host whose link has no recorder, and the shell's wiring test uses
    /// it to prove the recorder reached the host.
    pub fn count_frame_sent(&mut self, event: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "frames_sent_total",
                [("event".to_owned(), event.to_owned())],
            ));
        }
    }

    /// Counts one link this host opened.
    ///
    /// Recorded where the session opens rather than when it closes, because that is the event: a link that opened and
    /// then failed to be marked ready **did** open, and a count that hid it would make two different failures look
    /// like one.
    pub fn count_link_opened(&mut self) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "links_opened_total",
                Vec::new(),
            ));
        }
    }

    /// Counts one link the listener stopped serving, by why it ended.
    ///
    /// # Why this is recorded by the listener and not by the session registry
    ///
    /// Because the reason lives in the read loop: a `Bye` is `Closed`, a peer that went quiet is `TimedOut`, a frame the
    /// decoder refused is `protocol`, and the loop is the only place that knows which happened. The registry closes a
    /// session with a reason of its own, but that reason names the **session** lifecycle, not the wire's last moment.
    pub fn count_link_closed(&mut self, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "links_closed_total",
                [("reason".to_owned(), reason.to_owned())],
            ));
        }
    }

    /// Counts one attempt to deliver a late answer, by outcome.
    ///
    /// # Why the counter is not named `reconnect_attempts_total`
    ///
    /// Because this device does not reconnect: it dials the origin of an answer once, retries a bounded number of times,
    /// and gives up. The design names a counter for a mechanism that does not exist yet; giving this one the truthful name
    /// keeps "the kernel retried a late answer" from being read as "the kernel keeps links alive".
    pub fn count_late_delivery(&mut self, outcome: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "late_delivery_attempts_total",
                [("outcome".to_owned(), outcome.to_owned())],
            ));
        }
    }

    /// Counts one frame this host received, by event.
    ///
    /// ★ A separate method rather than one with a direction: a device that talks more than it is told, and one that is
    /// told more than it talks, are two different situations. Since the frame counters moved onto `PeerLink` — which sees
    /// every frame, including the ones a dialled link writes outside this host — **nothing in production calls this**. It
    /// is kept because a host whose link has no recorder still needs a way to say "this frame arrived", and the shell's
    /// wiring test uses it; a caller that counts both this and the link would double the frame.
    pub fn count_frame_received(&mut self, event: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "frames_received_total",
                [("event".to_owned(), event.to_owned())],
            ));
        }
    }
}
