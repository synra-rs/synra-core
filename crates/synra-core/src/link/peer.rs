use super::*;

impl PeerLink {
    /// Wraps a completed handshake.
    ///
    /// # Why the identifiers are arguments rather than read from the socket
    ///
    /// Because they came from the handshake, and a link that re-derived them from the first envelope it saw would be one
    /// a peer could address by claiming a different `from` — which is the check this type exists to make.
    #[must_use]
    pub fn new(
        stream: impl LinkStream + 'static,
        local: DeviceId,
        peer: DeviceId,
        agreed: synra_protocol::handshake::Agreed,
        flags: Flags,
    ) -> Self {
        Self {
            stream: Box::new(stream),
            decoder: FrameDecoder::new(),
            local,
            peer,
            agreed,
            flags,
            read_timeout_override: None,
            write_timeout_override: None,
            sent: 0,
            received: 0,
            metrics: None,
        }
    }

    /// Counts payload bytes into `metrics`.
    ///
    /// ★ A builder rather than a constructor argument: every existing caller keeps working, and the one place that builds
    /// a link from a dial (`Dialled::into_link`) is also the one place that now passes a recorder.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<synra_observe::metrics::RingRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Adds to one of the two byte counters, when this link has a recorder.
    pub(super) fn count_bytes(&self, metric: &str, bytes: usize) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_add(
                &synra_observe::metrics::SeriesKey::new(metric, []),
                u64::try_from(bytes).unwrap_or(u64::MAX),
            );
        }
    }

    /// Counts one envelope frame by its event, in the direction named by `metric`.
    ///
    /// ★ Here rather than in `Host::send`, which was the first home of `frames_sent_total`. The host only sees the frames a
    /// caller routes through it; a dialled link that sends an offer or a pairing request writes straight to the socket, and
    /// those frames were invisible. The link is the one object every frame passes, so this is where "what did this device
    /// say" can be answered for all of them — and `Host::send` no longer counts, because two counters for one frame would
    /// double every routed message.
    pub(super) fn count_frame(&self, metric: &str, event: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                metric,
                [("event".to_owned(), event.to_owned())],
            ));
        }
    }

    /// Reports a sent frame, and does not even build its peer string when no console is listening.
    ///
    /// ★ The guard is the point: `WireEvent::sent` takes text, so a call that allocated and then found no sink would make
    /// every ordinary send pay for a debug view nobody opened. The event name is already a `&str`, so the only avoidable
    /// work is `DeviceId::to_string` — and with a daemon (which never installs a sink) that is every frame.
    pub(super) fn trace_sent(&self, label: &str, bytes: usize) {
        if synra_observe::wire::is_installed() {
            synra_observe::wire::emit(&synra_observe::wire::WireEvent::sent(
                self.peer.to_string(),
                label,
                bytes,
            ));
        }
    }

    /// Reports a received frame; see [`PeerLink::trace_sent`] for why the guard lives here.
    pub(super) fn trace_received(&self, label: &str, bytes: usize) {
        if synra_observe::wire::is_installed() {
            synra_observe::wire::emit(&synra_observe::wire::WireEvent::received(
                self.peer.to_string(),
                label,
                bytes,
            ));
        }
    }

    /// This device.
    #[must_use]
    pub const fn local(&self) -> DeviceId {
        self.local
    }

    /// The device on the other end.
    #[must_use]
    pub const fn peer(&self) -> DeviceId {
        self.peer
    }

    /// What both ends agreed on.
    #[must_use]
    pub const fn agreed(&self) -> &synra_protocol::handshake::Agreed {
        &self.agreed
    }

    /// Whether a feature is available on this link.
    #[must_use]
    pub fn supports(&self, feature: synra_protocol::handshake::Feature) -> bool {
        self.agreed.supports(feature)
    }

    /// Envelopes sent on this link.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Envelopes accepted from this link.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }
}
