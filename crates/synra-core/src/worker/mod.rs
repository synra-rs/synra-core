//! The discovery worker: one thread answering queries and asking its own.
//!
//! # Why this is a thread rather than a call
//!
//! The control socket is served **one connection at a time** — `synra-control`'s `Listener::serve_one` blocks, and the
//! listener cannot be cloned, so a second client waits for the first to finish. That is fine for commands that answer
//! from memory, and it is not fine for discovery: a scan is a bounded wait on a network, and a scan that held the control
//! loop would make every other command — including the `status` a user runs to find out why things are slow — wait for
//! the network as well.
//!
//! So discovery runs on its own thread and the control loop only ever *reads* what that thread has learned. The thread
//! owns both sockets:
//!
//! * The **responder**, bound to the well-known discovery port, which answers queries from other devices. A device that
//!   did not answer would be one nothing on the network could find — it would have to be typed in by address.
//! * The **querier**, on a port the operating system chooses, which broadcasts this device's own queries. Broadcasts go
//!   out from here rather than from the responder because a reply is unicast back to **the address the query came from**,
//!   and a device that queried from the well-known port would have every answer arrive on the socket it shares with every
//!   other device on the machine.
//!
//! # What the thread does, once per tick
//!
//! 1. Reads whatever is waiting on the responder, one datagram at a time, and answers each query. The read has a timeout
//!    so the loop can also do the rest of its work; a socket with no timeout would sit here until a packet arrived and
//!    never broadcast.
//! 2. Reads whatever is waiting on the querier, which is where the answers to this device's own queries arrive.
//! 3. Broadcasts a query if the interval has come round again.
//!
//! # Why the interval is longer than a scan's budget
//!
//! Because a query is a broadcast, and a device that broadcast every second would be one that every machine on the
//! network sees every second — for a device that is already in their tables. The protocol's own scan budget is how long
//! *one* scan listens, and that is a different figure from how often the question is asked.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use synra_protocol::discovery::{DeviceAnnouncement, OfflineAnnouncement};

use crate::discovery::{Absorbed, DiscoveryTable};
use crate::host::Host;
use crate::socket::{DiscoverySocket, SocketError};

/// How often this device broadcasts its own query.
///
/// Not the scan budget: that is how long one scan listens, and this is how often the question is asked. Twice the
/// candidate lifetime would be too slow to notice a device appearing, and a second would make every machine on the
/// network read a broadcast every second for a device it already knows about.
pub const QUERY_INTERVAL: Duration = Duration::from_secs(20);

/// How long the responder waits for a datagram before doing the rest of its work.
///
/// Short, because it is not a deadline for anything: the loop comes back round, reads again, and in between checks
/// whether it is time to broadcast. A long timeout here would delay the broadcast, and a zero one would spin.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// What one pass of the worker did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ticked {
    /// Datagrams that told the kernel about a device.
    pub absorbed: Vec<Absorbed>,
    /// Addresses that asked a question and are waiting for an answer.
    ///
    /// Reported rather than answered inside the tick, because an answer needs this device's own announcement and a socket
    /// — neither of which the host owns. Keeping the two apart is what lets `tick` be tested without a network at all.
    pub askers: Vec<std::net::SocketAddr>,
    /// Whether this pass broadcast a query of its own.
    pub broadcast: bool,
    /// What went wrong, if anything.
    ///
    /// A failure is reported rather than acted on: a machine with no network, a firewall, and a sandbox all produce the
    /// same thing, and none of them is a reason for the kernel to stop. Discovery is how peers are *found*, not how they
    /// are reached.
    pub errors: Vec<SocketError>,
}

/// The two sockets discovery needs, plus where the answers go.
pub struct DiscoveryService {
    /// Bound to the well-known port; answers queries.
    responder: DiscoverySocket,
    /// The port the operating system chose; broadcasts this device's queries.
    querier: DiscoverySocket,
    /// What this device announces.
    ours: DeviceAnnouncement,
    /// When the next broadcast is due.
    next_query: Instant,
    /// How often to broadcast.
    interval: Duration,
    /// Whether the previous tick broadcast, so a scan's re-broadcasts become one console line rather than dozens.
    broadcasting: bool,
}

impl std::fmt::Debug for DiscoveryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryService")
            .field("device_id", &self.ours.device_id)
            .field("port", &self.ours.port)
            .field("interval", &self.interval)
            .finish()
    }
}

mod runner;
mod service;

pub use runner::{is_visible, run, run_recording};

#[cfg(test)]
mod round_trip_tests;
#[cfg(test)]
mod tests;
