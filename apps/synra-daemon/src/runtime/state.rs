use std::path::PathBuf;

use synra_core::{Host, Identity};

/// What the daemon knows about itself.
pub struct Runtime {
    /// The kernel's version, for a bug report.
    pub version: String,
    /// Where the data lives.
    pub data_dir: PathBuf,
    /// Where plugins are installed.
    pub plugins_dir: PathBuf,
    /// The transport port.
    pub listen_port: u16,
    /// The discovery port.
    pub discovery_port: u16,
    /// When the host started, in milliseconds since the epoch.
    ///
    /// A wall clock rather than a monotonic reading, because it is reported to a *client* — a separate process, whose
    /// monotonic clock is not comparable with this one. The same reasoning the claim file follows.
    pub started_at_ms: u64,
    /// This device's identity.
    ///
    /// # Why the runtime holds it rather than reading it each time
    ///
    /// Because reading it is how a device gets a **second** identity: [`Identity::load`] creates one when the row is
    /// absent, so a caller that read it per request would be creating one per request if the write ever failed. The
    /// daemon reads it once at start-up, after the claim, and everything after that uses that value.
    pub identity: Identity,
    /// The kernel's view of its peers: who it is, who it heard of, who it is talking to.
    ///
    /// # Why this is behind its own lock rather than the runtime's
    ///
    /// Because `Kernel`'s methods take `&self` while the accept loop holds the runtime for the duration of a connection.
    /// One lock over both would mean a device listing waits for a socket read, which is exactly the case that must not
    /// happen: a report is what a user runs *while* something is wrong.
    pub host: std::sync::Arc<parking_lot::Mutex<Host>>,
    /// The discovery service, when this kernel could bind one.
    ///
    /// `None` rather than a failure, because a machine with no network, a firewall, and a sandbox all produce the same
    /// thing — and a kernel that could not start without discovery would be one that cannot run with its wireless
    /// switched off. Discovery is how peers are *found*, not how they are reached.
    pub discovery: Option<std::sync::Arc<parking_lot::Mutex<synra_core::DiscoveryService>>>,
    /// When a scan should stop, as a wall-clock reading, or zero for none.
    ///
    /// # Why a deadline rather than a flag
    ///
    /// Because the client asks for a *duration* and the worker asks itself "is now before that". A flag would have to be
    /// cleared by whoever set it, and a client that disconnected mid-scan would leave it set — so the kernel would
    /// broadcast for ever. A deadline expires on its own, which is the property that matters when the process that asked
    /// is no longer there.
    pub scan_until_ms: std::sync::Arc<std::sync::atomic::AtomicI64>,
    /// The kernel's database.
    ///
    /// # Why the runtime holds it rather than the caller
    ///
    /// Because the commands that read it are the runtime's, and a caller that had to pass it in would be one that could
    /// pass a different database from the one the daemon claimed. The claim is about the *data directory*, and the
    /// database is derived from it — so holding both here is what keeps them from being able to disagree.
    pub db: synra_store::SynraDb,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection is not printable, and printing a database handle would leak its path into a log line. The rest
        // is, so it is listed rather than omitted.
        f.debug_struct("Runtime")
            .field("version", &self.version)
            .field("data_dir", &self.data_dir)
            .field("plugins_dir", &self.plugins_dir)
            .field("listen_port", &self.listen_port)
            .field("discovery_port", &self.discovery_port)
            .field("started_at_ms", &self.started_at_ms)
            .field("db", &"SynraDb")
            .finish()
    }
}

/// The wall clock, in milliseconds since the epoch.
///
/// # Why the wall clock and not a monotonic reading
///
/// The value is reported to a **separate process**, and a monotonic reading is only comparable within one. A client
/// subtracting its own monotonic clock from this would compute a nonsense uptime, and the same mistake in the claim file
/// is what made crash recovery never fire.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}
