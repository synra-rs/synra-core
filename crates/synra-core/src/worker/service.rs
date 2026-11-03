use super::{
    DeviceAnnouncement, DiscoveryService, DiscoverySocket, Duration, Host, Instant,
    OfflineAnnouncement, POLL_INTERVAL, QUERY_INTERVAL, SocketError, Ticked,
};

impl DiscoveryService {
    /// Binds both sockets.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when either socket cannot be bound. A caller decides whether that is fatal: the daemon does
    /// not, because a kernel that could not start without discovery would be one that cannot run with its wireless
    /// switched off.
    pub fn bind(ours: DeviceAnnouncement) -> Result<Self, SocketError> {
        Self::bind_with_interval(ours, QUERY_INTERVAL)
    }

    /// Binds both sockets with a chosen broadcast interval, for a test that must not wait one out.
    ///
    /// # Errors
    ///
    /// As [`DiscoveryService::bind`].
    pub fn bind_with_interval(
        ours: DeviceAnnouncement,
        interval: Duration,
    ) -> Result<Self, SocketError> {
        Self::bind_on(ours, synra_protocol::limits::DISCOVERY_PORT, interval)
    }

    /// Binds both sockets, with the responder on a chosen port.
    ///
    /// # Why the port is a parameter when the protocol fixes it
    ///
    /// Because a caller may have a reason to move it — two kernels on one host for a test, or a network where the
    /// well-known port is taken by something else — and a flag that reported a port it did not use is worse than no flag.
    /// The **default** is the protocol's constant, which is what keeps two devices able to find each other: a device that
    /// listened somewhere else could not be found by anything that did not already know where to look.
    ///
    /// The querier stays on an ephemeral port, and that is not configurable. It is where the answers to this device's own
    /// queries arrive, and it is deliberately *not* the shared port — a device that queried from there would have every
    /// answer land on the socket it shares with every other device on the machine.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when either socket cannot be bound.
    pub fn bind_on(
        ours: DeviceAnnouncement,
        responder_port: u16,
        interval: Duration,
    ) -> Result<Self, SocketError> {
        Ok(Self {
            responder: DiscoverySocket::bind(std::net::SocketAddr::from((
                std::net::Ipv4Addr::UNSPECIFIED,
                responder_port,
            )))?,
            querier: DiscoverySocket::bind(std::net::SocketAddr::from((
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            )))?,
            ours,
            // Due immediately, so the first tick broadcasts rather than waiting an interval for a kernel that has just
            // started and has nothing in its table.
            next_query: Instant::now(),
            interval,
            broadcasting: false,
        })
    }

    /// The address the responder is bound to.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when it cannot be read.
    pub fn responder_address(&self) -> Result<std::net::SocketAddr, SocketError> {
        self.responder.local_addr()
    }

    /// The address the querier is bound to, which is where answers arrive.
    ///
    /// # Errors
    ///
    /// [`SocketError::Bind`] when it cannot be read.
    pub fn querier_address(&self) -> Result<std::net::SocketAddr, SocketError> {
        self.querier.local_addr()
    }

    /// Runs one pass.
    ///
    /// `now_ms` is the wall clock the table records; `now` is the monotonic clock the broadcast interval is measured
    /// against. They are two different clocks on purpose: the first goes into a database and to a client, and the second
    /// only has to be steady — a wall clock that stepped backwards would stop the broadcasts entirely.
    /// `on_demand` is a deadline another thread has published — a client that asked for a scan — and a tick before it
    /// broadcasts whatever the interval says.
    pub fn tick(&mut self, host: &mut Host, now_ms: i64, now: Instant, on_demand: i64) -> Ticked {
        let mut ticked = Ticked::default();

        // The responder first: a query that arrives while this device is broadcasting is another device waiting for an
        // answer, and making it wait for a broadcast to finish is making it wait for no reason.
        self.drain(host, now_ms, &mut ticked, Which::Responder);
        // Then the querier, where the answers to this device's own queries arrive.
        self.drain(host, now_ms, &mut ticked, Which::Querier);

        // ★ A client's scan is why this exists. Without it the answer to "look for devices now" would be "wait up to
        // `QUERY_INTERVAL` for the next scheduled broadcast", which is a scan that finds nothing for twenty seconds and
        // then finds everything — the worst of both.
        let demanded = on_demand > 0 && now_ms < on_demand;
        if now >= self.next_query || demanded {
            // ★ One line per burst. A scan re-broadcasts on every tick until its deadline; one line per attempt would
            // bury the pairing frames the console exists to show. The first broadcast is the interesting one.
            if !self.broadcasting {
                synra_observe::wire::note("lan", "query");
                self.broadcasting = true;
            }
            // ★ Each address is reported on its own. "Nothing was found" and "nothing could be asked" are different
            // answers, and one failure among several interfaces is not a failure of the scan.
            for (_, result) in self.querier.broadcast_query(&self.ours) {
                if let Err(error) = result {
                    ticked.errors.push(error);
                }
            }
            ticked.broadcast = true;
            // The next one is measured from now rather than from the last due time, so a tick that ran late does not
            // produce a burst of catch-up broadcasts. A demanded broadcast does **not** push the scheduled one back any
            // further than the interval already does, so a scan does not delay the next scheduled query by a full
            // interval on top of the scan itself.
            self.next_query = now + self.interval;
        } else {
            self.broadcasting = false;
        }

        ticked
    }

    /// Reads every datagram waiting on one socket.
    fn drain(&self, host: &mut Host, now_ms: i64, ticked: &mut Ticked, which: Which) {
        let socket = match which {
            Which::Responder => &self.responder,
            Which::Querier => &self.querier,
        };
        // A short timeout rather than a blocking read, so a socket with nothing waiting does not hold the loop.
        if let Err(error) = socket.set_read_timeout(Some(POLL_INTERVAL / 8)) {
            ticked.errors.push(error);
            return;
        }

        // Bounded, so a device flooding the port cannot hold the loop for ever. Whatever is left waits for the next tick,
        // and a peer that filled this budget has already been heard from.
        for _ in 0..MAX_DATAGRAMS_PER_TICK {
            match socket.receive_packet(host, now_ms) {
                Ok(Some(packet)) => {
                    // Every query gets an answer, including unchanged announcements. Responses and goodbyes never do.
                    if let Some(source) = packet.reply_to {
                        ticked.askers.push(source);
                    }
                    ticked.absorbed.push(packet.absorbed);
                }
                // A datagram about this device, which is the ordinary case for a broadcast.
                Ok(None) => {}
                // A timeout, which is what an idle socket does and is not news.
                // A timeout is what an idle socket does and is not news. Windows reports it as `WSAETIMEDOUT` rather
                // than as a would-block, which is why this is matched on the variant rather than on an error kind.
                Err(SocketError::Receive { .. }) => return,
                // ★ A query has to be *answered*, and this is the only place that can: it needs the socket it arrived on
                // and this device's own announcement. The table has already absorbed it, because a device that asks is a
                // device that exists.
                Err(SocketError::Malformed { .. }) => return,
                Err(error) => {
                    ticked.errors.push(error);
                    return;
                }
            }
        }
    }

    /// Answers one device.
    ///
    /// # Errors
    ///
    /// [`SocketError::Send`] when the answer cannot be sent. A query that cannot be answered is reported rather than
    /// retried: the device that asked will ask again on its next broadcast.
    pub fn answer(&self, to: std::net::SocketAddr) -> Result<usize, SocketError> {
        self.responder.send_response(&self.ours, to)
    }

    /// Answers every device that asked during a tick.
    ///
    /// # Why this is separate from the tick
    ///
    /// Because an answer sends on a socket, and the socket is here while the table is the host's. Keeping them apart is
    /// what makes the decision — *who asked and is waiting* — testable without a network, and a send is the part that
    /// only a network can be wrong about.
    ///
    /// Returns one result per asker, because one address failing is not a failure of the others.
    #[must_use]
    pub fn answer_pending(
        &self,
        ticked: &Ticked,
    ) -> Vec<(std::net::SocketAddr, Result<usize, SocketError>)> {
        ticked
            .askers
            .iter()
            .map(|address| (*address, self.responder.send_response(&self.ours, *address)))
            .collect()
    }

    /// Announces that this device is leaving.
    ///
    /// # Errors
    ///
    /// Never — the failures are returned in the list, one per address, because a device that is shutting down has no
    /// second chance and every interface deserves its own attempt.
    #[must_use]
    pub fn goodbye(
        &self,
        timestamp: i64,
    ) -> Vec<(std::net::SocketAddr, Result<usize, SocketError>)> {
        self.querier.broadcast_offline(&OfflineAnnouncement {
            device_id: self.ours.device_id,
            timestamp,
        })
    }
}

/// How many datagrams one pass will read from one socket.
const MAX_DATAGRAMS_PER_TICK: usize = 64;

/// Which of the two sockets is being drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    /// The well-known port, where queries arrive.
    Responder,
    /// The ephemeral port, where answers arrive.
    Querier,
}
