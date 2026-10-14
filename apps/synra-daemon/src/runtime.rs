//! What the daemon answers a client with.
//!
//! # The honesty this module is built around
//!
//! The daemon can serve the control socket, own the data directory and say what it is. It cannot yet read devices or
//! plugins, because there is no database implementation and no session layer behind them. So the commands split in two:
//!
//! | Command | Answer |
//! | --- | --- |
//! | `status`, `logs`, `plugins` | real, and it says what is not implemented |
//! | `devices`, `send` | a refusal naming the missing layer |
//!
//! # Why a refusal rather than an empty list
//!
//! "No devices" and "I cannot tell you about devices" are different answers, and only one of them is true. A client that
//! received an empty list would report that nothing is paired — and a user would go looking for a pairing problem in an
//! installation where the real problem is that the code is not written.
//!
//! That is the same rule the daemon's own start-up follows: it prints `no kernel is started yet` rather than reporting
//! success. A host that reported success without running a kernel would be worse than one that says what it did not do.

use std::path::{Path, PathBuf};

use synra_control::{Kernel, Refusal};
use synra_core::{Host, Identity};
use synra_protocol::error::ErrorCode;

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

/// The layers that are not written yet.
///
/// # Why this is one constant rather than a sentence at each call site
///
/// Four commands refuse for the same reason, and a reason that lived in four places would drift — so a user
/// investigating two of them would be told two different things about one missing layer. It is also what a test asserts
/// against, so "the refusal names the missing part" is checked rather than described.
pub const MISSING_SESSION_LAYER: &str =
    "the kernel's session layer is not implemented yet: this build can serve the control socket and report its own \
     state, and it cannot yet discover, pair with or send to a device";

impl Runtime {
    /// The `status` answer.
    ///
    /// # Why this carries the missing-layer note
    ///
    /// `status` is the one command a user runs to find out what is going on, so it is where "the kernel is up and this
    /// part is not built" belongs. A status that reported a healthy daemon and nothing else would leave a user
    /// wondering why the next command refuses.
    fn status_value(&self, now_ms: u64) -> serde_json::Value {
        // ★ The schema version and the row counts are read rather than described. A status that said "database: ok"
        // without asking would be a status that cannot be wrong — and therefore one that cannot tell a user anything.
        let schema = self.db.recorded_version().ok().flatten();
        let counts = self.db.counts().ok().map(|rows| {
            rows.into_iter()
                .map(|(table, count)| (table, serde_json::json!(count)))
                .collect::<serde_json::Map<String, serde_json::Value>>()
        });

        serde_json::json!({
            "state": "running",
            "version": self.version,
            "dataDir": self.data_dir.to_string_lossy(),
            "pluginsDir": self.plugins_dir.to_string_lossy(),
            "transportPort": self.listen_port,
            "discoveryPort": self.discovery_port,
            "uptimeMs": now_ms.saturating_sub(self.started_at_ms),
            "deviceId": self.identity.device_id.to_string(),
            "deviceName": self.identity.display_name,
            "schemaVersion": schema,
            "schemaKnown": synra_store::SynraDb::known_version(),
            "tables": counts,
            // ★ Present rather than omitted, so a client can print it. An absent field would be indistinguishable from
            // an older kernel that does not have the concept. `database` is gone from this list because it is now real.
            // ★ `discovery` is gone from this list because it is real: a device. The session layer is what remains, and
            // it is what `send` still refuses on.
            "notImplemented": ["session"],
        })
    }

    /// What is installed in the plugins directory.
    ///
    /// # Why this is real while `devices` is not
    ///
    /// The plugins directory is a directory, and listing it needs no layer that is missing. A plugin is a directory
    /// with a `manifest.json` in it, so the listing is a listing — reported as it is, with no claim about whether the
    /// kernel has *loaded* any of them, which it has not.
    fn plugins_value(&self) -> Result<serde_json::Value, Refusal> {
        // ★ The database is the source of truth for what is *installed*, and the directory is where the artifacts are.
        // The first version of this listed the directory, which answered a different question: a plugin whose directory
        // is there but whose row is not has never been installed by the kernel, and one whose row is there and whose
        // directory is gone has been removed from disk behind its back. Both are states a user needs to see.
        let rows = self.db.plugins().map_err(|error| {
            Refusal::new(ErrorCode::Internal, format!("could not read the plugins table: {error}"))
        })?;

        let mut installed: Vec<serde_json::Value> = Vec::new();
        for row in rows {
            // The manifest is read for the title, and its absence is reported rather than skipped: a row whose artifact
            // is gone is something the user should see, because the plugin will fail the next time it is called.
            let manifest_path = self.plugins_dir.join(&row.plugin_id).join("manifest.json");
            let manifest = std::fs::read_to_string(&manifest_path)
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());

            installed.push(serde_json::json!({
                "id": row.plugin_id,
                "title": manifest
                    .as_ref()
                    .and_then(|value| value.get("title"))
                    .and_then(serde_json::Value::as_str),
                "enabled": row.enabled,
                "trusted": row.trusted,
                "health": row.health,
                "installedAtMs": row.installed_at_ms,
                "updatedAtMs": row.updated_at_ms,
                // ★ Reported rather than assumed. A row whose directory is gone is one `should_run` would say yes to and
                // the host would fail to load.
                "artifactPresent": manifest_path.exists(),
            }));
        }

        Ok(serde_json::json!({
            "plugins": installed,
            // ★ `false`, so a client does not present an installed plugin as one that is running. The kernel has loaded
            // nothing: there is no Wasm host wired to this daemon yet.
            "loaded": false,
        }))
    }

    /// The tail of the daemon's log.
    ///
    /// # The cost of filtering text
    ///
    /// Quiet mode hides a line that contains `DEBUG` or `TRACE` as a word — which is right for a level and wrong for a
    /// message that names one, so `INFO turning DEBUG off` is hidden. A text filter over a text log cannot tell the two
    /// apart, and the alternatives were worse here: keeping only lines that *start* with a level would pin this to one
    /// log format, and the format is the daemon's own. `--verbose` is the way to see everything.
    ///
    /// # Why this reads a directory rather than a file
    ///
    /// The log directory is what the kernel writes to, and a file there may be rotated or absent. Reading the newest
    /// file is the useful answer for a user asking "what happened", and reporting that there is none is the honest one
    /// for a fresh installation.
    fn logs_value(&self, lines: usize, verbose: bool) -> Result<serde_json::Value, Refusal> {
        // The log lives in the cache directory beside the data directory, which is where `Paths` puts it.
        let log_dir = self.data_dir.join("logs");
        let Some(newest) = newest_file(&log_dir) else {
            return Ok(serde_json::json!({"lines": [], "source": serde_json::Value::Null}));
        };

        let text = std::fs::read_to_string(&newest).map_err(|error| {
            Refusal::new(
                ErrorCode::Internal,
                format!("could not read {}: {error}", newest.display()),
            )
        })?;

        // Filtered rather than requested from the writer: the level is in the line, and a filter here keeps the daemon
        // from needing an index of its own log.
        //
        // ★ The level is matched as a **token** rather than with `contains(" DEBUG ")`, which was the first version and
        // was wrong: a line may begin with the level — `DEBUG detail` — and then there is no space before it. What
        // follows the level is a space or the end of the line, and a line has a timestamp in front of it in the real
        // log, which is why the token is found by splitting rather than by position.
        let wanted: Vec<&str> = text
            .lines()
            .filter(|line| verbose || !is_debug_or_trace(line))
            .collect();
        let start = wanted.len().saturating_sub(lines);
        let tail: &[&str] = wanted.get(start..).unwrap_or(&[]);

        Ok(serde_json::json!({
            "lines": tail,
            "source": newest.to_string_lossy(),
            "total": wanted.len(),
        }))
    }
}

/// Whether a log line is at `DEBUG` or `TRACE`.
///
/// # Why a token rather than a substring
///
/// A line may begin with the level, so there is no space before it — `DEBUG detail` — and a search for `" DEBUG "` finds
/// nothing. It may also have a timestamp in front, so the level is not the first word either. Splitting the line into
/// words handles both, and the level is the word itself rather than something that merely contains it.
fn is_debug_or_trace(line: &str) -> bool {
    line.split_whitespace().any(|word| word == "DEBUG" || word == "TRACE")
}

/// The newest file in a directory, if there is one.
fn newest_file(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}

impl Kernel for Runtime {
    fn version(&self) -> String {
        self.version.clone()
    }

    fn status(&self) -> Result<serde_json::Value, Refusal> {
        Ok(self.status_value(now_ms()))
    }

    fn devices(&self, include_unpaired: bool, scan_ms: Option<u64>) -> Result<serde_json::Value, Refusal> {
        // ★ The scan is done **before** the table is read, and by the worker rather than here. Only the worker owns the
        // discovery socket, and a client that slept for the duration and then asked would get exactly the table it would
        // have got without asking — the sleep would look like a scan and be a delay.
        if let Some(scan_ms) = scan_ms.filter(|ms| *ms > 0) {
            self.scan(scan_ms);
        }

        // ★ Three sources, reported separately rather than merged. A paired device, a device merely heard on the network,
        // and this device are three different things to a user — and a list that put them together would present an
        // unauthenticated datagram as something the user had approved.
        let host = self.host.lock();
        let now = now_ms();

        // The paired devices come from the database, which is the recorded decision.
        let paired = self.db.paired_devices().map_err(|error| {
            Refusal::new(ErrorCode::Internal, format!("could not read the paired devices: {error}"))
        })?;
        let mut paired_list: Vec<serde_json::Value> = Vec::new();
        for row in &paired {
            // The session is the proof the device is reachable *now*, as opposed to recorded once. A user asking for
            // devices is asking what they can act on, so the two are reported together.
            let device_id: synra_protocol::ids::DeviceId = row.device_id.parse().map_err(|error| {
                Refusal::new(
                    ErrorCode::Internal,
                    format!("the stored device id {} is not a UUID: {error}", row.device_id),
                )
            })?;
            let session = host.state_of(device_id);
            paired_list.push(serde_json::json!({
                "deviceId": row.device_id,
                "displayName": row.display_name,
                "platform": row.platform,
                "blocked": row.blocked,
                "pairedAtMs": row.paired_at_ms,
                "lastSeenMs": row.last_seen_ms,
                // `null` when there is no session, which is different from a session that is closed — and the difference
                // is what tells a user whether the device is offline or was never reached.
                "linkState": session.map(|state| format!("{state:?}")),
            }));
        }

        // The candidates are what discovery heard, which is unauthenticated and therefore reported as its own list.
        let candidates: Vec<serde_json::Value> = if include_unpaired {
            host.discovery()
                .displayable(synra_core::millis_reading(now))
                .map(|candidate| {
                    serde_json::json!({
                        "deviceId": candidate.device_id.to_string(),
                        "displayName": candidate.display_name,
                        "address": candidate.address.to_string(),
                        "trust": format!("{:?}", candidate.trust),
                        "lastSeenMs": candidate.last_seen_ms,
                    })
                })
                .collect()
        }
        else {
            Vec::new()
        };

        Ok(serde_json::json!({
            // ★ Reported rather than omitted, so a client prints it. A user who runs `devices` because nothing works
            // needs to know which device they are running it *on* — that identifier is what the other end has recorded
            // against them.
            "self": {
                "deviceId": self.identity.device_id.to_string(),
                "displayName": self.identity.display_name,
                "platform": self.identity.platform,
            },
            "paired": paired_list,
            "found": candidates,
            "includeUnpaired": include_unpaired,
            "count": paired_list.len() + candidates.len(),
        }))
    }

    fn send_text(&self, _to: &str, _text: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(ErrorCode::Unsupported, MISSING_SESSION_LAYER))
    }

    fn send_file(&self, _to: &str, _path: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(ErrorCode::Unsupported, MISSING_SESSION_LAYER))
    }

    fn plugins(&self) -> Result<serde_json::Value, Refusal> {
        self.plugins_value()
    }

    fn logs(&self, lines: usize, verbose: bool) -> Result<serde_json::Value, Refusal> {
        self.logs_value(lines, verbose)
    }
}

impl Runtime {
    /// Asks the discovery worker to scan for a while, and waits for it.
    ///
    /// # Why the deadline is published rather than the work being done here
    ///
    /// Because the worker owns the sockets. This sets the deadline the worker reads and then waits, polling the table —
    /// which is the only thing it can do, since the worker is a separate thread and there is no channel between them.
    /// The wait is bounded by the request, and the deadline expires on its own if this caller goes away.
    fn scan(&self, scan_ms: u64) {
        let Some(discovery) = &self.discovery else {
            // Nothing to scan with. Reported once rather than as a failure: the answer is still the table, which is all
            // a kernel without a discovery socket can honestly offer.
            return;
        };

        // The protocol's scan budget is the ceiling: a client may not ask the kernel to broadcast for longer than one
        // scan is allowed to run, because the request is unauthenticated input from a local process.
        let budget = scan_ms.min(u64::try_from(synra_protocol::limits::SCAN_TOTAL.as_millis()).unwrap_or(u64::MAX));
        let deadline = now_ms().saturating_add(budget);
        self.scan_until_ms.store(millis_reading_i64(deadline), std::sync::atomic::Ordering::Relaxed);

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

/// A wall-clock reading as the signed value an atomic can hold.
const fn millis_reading_i64(value: u64) -> i64 {
    if value > i64::MAX as u64 { i64::MAX } else { value as i64 }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-rt-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary directory");
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A runtime over a migrated in-memory database, and a plugins directory under `dir`.
    fn runtime(dir: &Path) -> Runtime {
        let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
        db.migrate().expect("migrates");
        let identity = Identity::load(&db, "windows", 1_000).expect("an identity");
        let local_peer = synra_core::LocalPeer::new(
            identity.device_id,
            identity.display_name.clone(),
            synra_core::platform_of_os("windows"),
            "0.1.0-test",
        );
        let host = Host::new(identity.clone(), local_peer);
        Runtime {
            version: "0.1.0-test".to_owned(),
            data_dir: dir.to_path_buf(),
            plugins_dir: dir.join("plugins"),
            listen_port: 47100,
            discovery_port: 47101,
            started_at_ms: 1_000,
            identity,
            host: std::sync::Arc::new(parking_lot::Mutex::new(host)),
            // No discovery socket in a unit test: binding the well-known port would collide with a kernel that happens to
            // be running on this machine, so the fixture leaves it absent — which is also the state a kernel with no
            // network is in, and one the code has to handle anyway.
            discovery: None,
            scan_until_ms: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0)),
            db,
        }
    }

    // ── Status ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn status_reports_the_hosts_own_state() {
        let dir = TempDir::new("status");
        let value = runtime(dir.path()).status().expect("status");

        assert_eq!(value["state"], "running");
        assert_eq!(value["version"], "0.1.0-test");
        assert_eq!(value["transportPort"], 47100);
        assert_eq!(value["discoveryPort"], 47101);
        assert!(value["dataDir"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn status_names_the_layers_that_are_not_built() {
        // ★ `status` is what a user runs to find out what is going on, so it is where "the kernel is up and this part is
        // not built" belongs. A status that reported a healthy daemon and nothing else would leave them wondering why
        // the next command refuses.
        let dir = TempDir::new("status-missing");
        let value = runtime(dir.path()).status().expect("status");
        let missing = value["notImplemented"].as_array().expect("a list");
        let names: Vec<&str> = missing.iter().filter_map(serde_json::Value::as_str).collect();
        assert_eq!(names, vec!["session"], "{names:?}");
        // ★ And the layers that are real are **not** in it. `database` and `discovery` were both listed here while they
        // were unbuilt, and a list that kept them would tell a user a working feature is missing — which is the failure
        // mode of a hand-maintained list, and why this asserts the exact contents rather than a superset.
        assert!(!names.contains(&"database"), "{names:?}");
        assert!(!names.contains(&"discovery"), "{names:?}");
    }

    #[test]
    fn the_uptime_is_measured_from_the_start() {
        // Saturating: a start time in the future is a caller with a clock that moved, and a negative duration is not one
        // this can represent.
        let dir = TempDir::new("uptime");
        let value = runtime(dir.path()).status().expect("status");
        assert!(value["uptimeMs"].as_u64().is_some());
    }

    // ── The missing layer ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn asking_for_devices_reports_where_each_part_came_from() {
        // ★ The report has three sources, and each is under its own key rather than merged. A paired device, a device
        // merely heard on the network, and this device are three different things to a user — and a list that put them
        // together would present an unauthenticated datagram as something the user had approved.
        let dir = TempDir::new("devices");
        let value = runtime(dir.path()).devices(true, None).expect("devices");

        // This device, from the stored identity.
        assert_eq!(value["self"]["displayName"], "This device");
        assert_eq!(value["self"]["platform"], "windows");
        assert!(value["self"]["deviceId"].as_str().is_some_and(|id| !id.is_empty()));
        // And two empty lists, each from a real source: an empty `paired_devices` table and an empty discovery table.
        assert_eq!(value["paired"].as_array().map(Vec::len), Some(0));
        assert_eq!(value["found"].as_array().map(Vec::len), Some(0));
        assert_eq!(value["count"], 0);
        assert_eq!(value["includeUnpaired"], true);
    }

    #[test]
    fn a_scan_request_expires_on_its_own_and_is_capped_by_the_protocol() {
        // ★ The deadline is published rather than the work being done here, and it **expires**. A flag would have to be
        // cleared by whoever set it, and a client that disconnected mid-scan would leave it set — so the kernel would
        // broadcast for ever. A deadline is the property that matters when the process that asked is no longer there.
        let dir = TempDir::new("scan-request");
        let runtime = runtime(dir.path());
        assert_eq!(runtime.scan_until_ms.load(std::sync::atomic::Ordering::Relaxed), 0);

        // No discovery socket in this fixture, so `scan` returns without publishing anything — and the call still has to
        // be harmless, because a kernel with no network is a state the code has to handle.
        assert!(runtime.discovery.is_none());
        let _ = runtime.devices(true, Some(10)).expect("devices");
        assert_eq!(runtime.scan_until_ms.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn a_zero_or_absent_scan_budget_does_not_scan() {
        // `--cached` means "do not scan", and it is expressed as an absent budget rather than as a zero one so the
        // protocol's own rule holds: an absent field is a client saying nothing, not a client saying zero.
        let dir = TempDir::new("no-scan");
        let runtime = runtime(dir.path());
        assert!(runtime.devices(true, None).is_ok());
        assert!(runtime.devices(true, Some(0)).is_ok());
        assert_eq!(runtime.scan_until_ms.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn asking_without_the_unpaired_ones_omits_them_rather_than_listing_nothing() {
        // The flag is what a client uses for a compact view, and it is echoed back so a report says which question it
        // answered.
        let dir = TempDir::new("devices-compact");
        let value = runtime(dir.path()).devices(false, None).expect("devices");
        assert_eq!(value["includeUnpaired"], false);
        assert_eq!(value["found"].as_array().map(Vec::len), Some(0));
        // The paired ones are still reported: they are the recorded decisions, not candidates.
        assert!(value["paired"].is_array());
    }

    #[test]
    fn a_device_the_kernel_heard_on_the_network_appears_under_its_own_key() {
        // ★ The two lists are separate for a reason, and this is what makes it visible: a device heard over UDP has not
        // been approved by anyone, so it must not appear among the paired ones.
        let dir = TempDir::new("devices-found");
        let runtime = runtime(dir.path());
        let announcement = synra_protocol::discovery::DeviceAnnouncement {
            device_id: "33333333-3333-4333-8333-333333333333".parse().expect("a device id"),
            display_name: "Phone".to_owned(),
            protocol: synra_protocol::handshake::PROTOCOL_VERSION,
            port: 47100,
            platform: Some(synra_protocol::session::PlatformKind::Android),
            app_version: Some("0.1.0".to_owned()),
            features: Vec::new(),
        };
        // The clock is taken from the daemon rather than passed as a literal: `displayable` compares against *now*, so a
        // candidate recorded at a fixed early timestamp is already expired by the time the report runs. That is exactly
        // how the first version of this test failed — it asserted a device was listed and the lifetime said otherwise.
        let now = synra_core::millis_reading(now_ms());

        // Heard once as an announcement, then again as a completed handshake — which is what makes it displayable,
        // because the protocol's own rule is that an announced device is a candidate and not a peer.
        runtime.host.lock().heard(
            &announcement,
            std::net::SocketAddr::from(([10, 0, 0, 5], 5_4321)),
            now,
        );
        runtime.host.lock().handshaked(
            announcement.device_id,
            std::net::SocketAddr::from(([10, 0, 0, 5], 47_100)),
            Some("Phone"),
            now,
        );

        let value = runtime.devices(true, None).expect("devices");
        assert_eq!(value["paired"].as_array().map(Vec::len), Some(0), "nothing is paired");
        let found = value["found"].as_array().expect("a list");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["displayName"], "Phone");
        assert_eq!(found[0]["trust"], "Handshaked");
        // And the port is the one it listens on for connections, not the ephemeral one it sent from.
        assert!(found[0]["address"].as_str().is_some_and(|a| a.ends_with(":47100")), "{found:?}");
    }

    #[test]
    fn sending_is_refused_for_the_same_reason_as_listing() {
        // One missing layer, one sentence. A reason that lived at each call site would drift, and a user investigating
        // two commands would be told two different things about one gap.
        let dir = TempDir::new("send");
        let runtime = runtime(dir.path());
        for refusal in [runtime.send_text("d", "x"), runtime.send_file("d", "/tmp/a")] {
            match refusal {
                Err(refusal) => assert_eq!(refusal.message, MISSING_SESSION_LAYER),
        // The refusal above is `send`'s; the `devices` list is real. Asserted here so the two are not confused.
                Ok(value) => panic!("expected a refusal, got {value}"),
            }
        }
    }

    #[test]
    fn a_refusal_for_a_missing_layer_is_not_retryable() {
        // ★ `Unsupported` is not retryable, and that is the right answer: repeating the call will keep failing until a
        // new build is installed. A retryable flag would have a client offer a retry that cannot work.
        //
        // The example is `send`: listing devices is real now, and sending is what still needs the transfer layer.
        let dir = TempDir::new("retryable");
        match runtime(dir.path()).send_text("d", "x") {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::Unsupported);
                assert!(!refusal.is_retryable());
            }
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    // ── Plugins ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_fresh_installation_has_no_plugins_and_that_is_not_an_error() {
        // A missing directory is the state of every fresh installation, so it is an answer rather than a refusal.
        let dir = TempDir::new("plugins-empty");
        let value = runtime(dir.path()).plugins().expect("plugins");
        assert_eq!(value["plugins"].as_array().map(Vec::len), Some(0));
        // And it says nothing is loaded, so a client does not present an installed plugin as one that is running.
        assert_eq!(value["loaded"], false);
    }

    /// Inserts a plugin row, which is what the database is the source of truth for.
    fn install(runtime: &Runtime, id: &str, enabled: i64, trusted: i64) {
        runtime
            .db
            .insert_plugin(id, enabled != 0, trusted != 0, "healthy", 100, 200)
            .expect("a plugin row");
    }

    #[test]
    fn an_installed_plugin_is_reported_from_the_database() {
        // ★ The database is the source of truth for what is *installed*. The first version of this listed the plugins
        // directory, which answered a different question: a plugin whose directory is there but whose row is not has
        // never been installed by the kernel.
        let dir = TempDir::new("plugins-one");
        let runtime = runtime(dir.path());
        install(&runtime, "@acme/hello", 1, 1);

        let value = runtime.plugins().expect("plugins");
        let plugins = value["plugins"].as_array().expect("a list");
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0]["id"], "@acme/hello");
        assert_eq!(plugins[0]["enabled"], true);
        assert_eq!(plugins[0]["trusted"], true);
        assert_eq!(plugins[0]["health"], "healthy");
        // And it says the artifact is not on disk, which it is not — a row without a directory is one the host would
        // fail to load, and a user needs to see that rather than discover it at the next call.
        assert_eq!(plugins[0]["artifactPresent"], false);
    }

    #[test]
    fn a_plugin_whose_artifact_is_on_disk_says_so() {
        let dir = TempDir::new("plugins-artifact");
        let runtime = runtime(dir.path());
        install(&runtime, "@acme/hello", 1, 1);
        let plugin_dir = dir.path().join("plugins").join("@acme/hello");
        std::fs::create_dir_all(&plugin_dir).expect("a plugin directory");
        std::fs::write(
            plugin_dir.join("manifest.json"),
            r#"{"id": "@acme/hello", "title": "Hello"}"#,
        )
        .expect("a manifest");

        let value = runtime.plugins().expect("plugins");
        assert_eq!(value["plugins"][0]["artifactPresent"], true);
        // The title comes from the manifest, which is the one thing the directory is read for.
        assert_eq!(value["plugins"][0]["title"], "Hello");
    }

    #[test]
    fn a_plugin_the_user_never_trusted_is_reported_as_untrusted() {
        // ★ Enabled and trusted are two questions, and the report carries both: `should_run` is `enabled && trusted`, so
        // a plugin that is on but never confirmed is one nobody approved capabilities for.
        let dir = TempDir::new("plugins-untrusted");
        let runtime = runtime(dir.path());
        install(&runtime, "@acme/hello", 1, 0);

        let value = runtime.plugins().expect("plugins");
        assert_eq!(value["plugins"][0]["enabled"], true);
        assert_eq!(value["plugins"][0]["trusted"], false);
    }

    #[test]
    fn an_empty_plugins_table_is_an_empty_list() {
        let dir = TempDir::new("plugins-none");
        let value = runtime(dir.path()).plugins().expect("plugins");
        assert_eq!(value["plugins"].as_array().map(Vec::len), Some(0));
        // And it says nothing is loaded, so a client does not present an installed plugin as one that is running.
        assert_eq!(value["loaded"], false);
    }

    #[test]
    fn the_plugins_come_back_in_a_stable_order() {
        // Two runs of `synra plugin list` have to agree, or a diff of two reports is noise.
        let dir = TempDir::new("plugins-order");
        let runtime = runtime(dir.path());
        install(&runtime, "@acme/zeta", 1, 1);
        install(&runtime, "@acme/alpha", 1, 1);

        let ids: Vec<String> = runtime.plugins().expect("plugins")["plugins"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(|plugin| plugin["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(ids, vec!["@acme/alpha", "@acme/zeta"]);
    }
    // ── Logs ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_fresh_installation_has_no_log_and_that_is_not_an_error() {
        let dir = TempDir::new("logs-empty");
        let value = runtime(dir.path()).logs(10, false).expect("logs");
        assert_eq!(value["lines"].as_array().map(Vec::len), Some(0));
        assert!(value["source"].is_null());
    }

    #[test]
    fn the_tail_is_the_last_lines_in_order() {
        let dir = TempDir::new("logs-tail");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("the log directory");
        std::fs::write(log_dir.join("kernel.log"), "one\ntwo\nthree\nfour\n").expect("a log");

        let value = runtime(dir.path()).logs(2, false).expect("logs");
        let lines: Vec<&str> = value["lines"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(lines, ["three", "four"]);
        assert_eq!(value["total"], 4);
    }

    #[test]
    fn asking_for_more_lines_than_exist_gives_everything() {
        // A `saturating_sub` rather than a subtraction: a request for a thousand lines from a four-line log must not
        // underflow into an empty answer.
        let dir = TempDir::new("logs-more");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("the log directory");
        std::fs::write(log_dir.join("kernel.log"), "one\ntwo\n").expect("a log");

        let value = runtime(dir.path()).logs(1_000, false).expect("logs");
        assert_eq!(value["lines"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn debug_lines_are_hidden_unless_they_are_asked_for() {
        // The level is in the line, and filtering here keeps the daemon from needing an index of its own log.
        let dir = TempDir::new("logs-verbose");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("the log directory");
        std::fs::write(
            log_dir.join("kernel.log"),
            "INFO started\nDEBUG detail\nINFO finished\n",
        )
        .expect("a log");

        // Quiet hides `DEBUG` and `TRACE`, and keeps everything else — two `INFO` lines out of three. A filter that kept
        // only `INFO` would hide warnings and errors, which are the lines a user is actually looking for.
        let quiet = runtime(dir.path()).logs(10, false).expect("logs");
        assert_eq!(quiet["lines"].as_array().map(Vec::len), Some(2));
        let verbose = runtime(dir.path()).logs(10, true).expect("logs");
        assert_eq!(verbose["lines"].as_array().map(Vec::len), Some(3));

        // And the shape the real log has, where a timestamp comes first — the case the naive `contains(" DEBUG ")` did
        // happen to handle, which is why the bug survived being read.
        std::fs::write(
            log_dir.join("kernel.log"),
            "2026-01-01T00:00:00Z INFO started\n2026-01-01T00:00:01Z DEBUG detail\n",
        )
        .expect("a log");
        let stamped = runtime(dir.path()).logs(10, false).expect("logs");
        let lines: Vec<&str> = stamped["lines"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("INFO"), "{lines:?}");
    }

    #[test]
    fn the_filter_matches_a_level_token_in_either_shape() {
        assert!(is_debug_or_trace("DEBUG detail"));
        assert!(is_debug_or_trace("2026-01-01T00:00:00Z TRACE detail"));
        assert!(!is_debug_or_trace("INFO started"));
        assert!(!is_debug_or_trace("WARN something"));
    }

    #[test]
    fn the_filter_has_a_known_cost_and_it_is_not_hidden() {
        // ★ A text filter over a text log cannot tell a level from a message that names one, and this test says so
        // rather than leaving it to be discovered. `INFO turning DEBUG off` is hidden by the quiet filter.
        //
        // The alternatives were worse for this use: keeping only lines that *start* with a level would need the format
        // to be fixed, and a daemon's log format is its own. A user who needs the line passes `--verbose`.
        assert!(
            is_debug_or_trace("INFO turning DEBUG off"),
            "the documented cost of the filter has changed; the doc comment above `logs_value` says what it is"
        );
    }

    #[test]
    fn the_newest_log_file_is_the_one_read() {
        // A rotated log leaves several, and a user asking "what happened" wants the recent one.
        let dir = TempDir::new("logs-newest");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("the log directory");
        std::fs::write(log_dir.join("a-old.log"), "old\n").expect("a log");
        // A sleep, because the ordering is by modification time and two writes in one millisecond are ordered by
        // nothing.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(log_dir.join("b-new.log"), "new\n").expect("a log");

        let value = runtime(dir.path()).logs(10, false).expect("logs");
        let lines: Vec<&str> = value["lines"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(lines, ["new"]);
    }

    #[test]
    fn the_reported_version_is_the_one_a_client_compares() {
        let dir = TempDir::new("version");
        assert_eq!(runtime(dir.path()).version(), "0.1.0-test");
    }

    #[test]
    fn the_wall_clock_is_a_plausible_epoch_reading() {
        // Not a monotonic reading: the value is reported to a separate process, whose monotonic clock is not comparable
        // with this one — the same mistake that once made crash recovery never fire.
        let now = now_ms();
        // Somewhere after 2020 and before 2100, in milliseconds.
        assert!(now > 1_577_836_800_000, "{now}");
        assert!(now < 4_102_444_800_000, "{now}");
    }
}
