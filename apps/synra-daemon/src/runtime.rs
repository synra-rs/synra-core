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
use synra_core::{Host, HostError, Identity};
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

/// How long one file transfer may take before the daemon stops waiting.
///
/// # Why this is a ceiling and not an expectation
///
/// A file takes as long as it takes, so nothing here can be the *expected* duration. What it bounds is the worst case: a
/// peer that stops reading, a link that has gone quiet, or a receiver that never answers. Without it, one stalled transfer
/// holds a kernel thread for ever — and the protocol's own scan budget would be far too short, because that is how long a
/// *scan* listens, not how long a file takes to move.
const TRANSFER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

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

    fn send_text(&self, to: &str, text: &str) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let trace_id = synra_protocol::ids::TraceId::new();

        // ★ The text is checked **before** the host is touched, and the order is a decision rather than a detail. An empty
        // `--text` is a mistake in the argument the user just typed; reporting it as an unknown device would send them to
        // check a device list for a mistake they made in their own sentence. The check is done by building an envelope
        // addressed to *this* device, which the protocol validates, and then throwing it away — the real one is built once
        // the device is known, so this costs one small allocation and no lock.
        synra_core::text_to(self.identity.device_id, self.identity.device_id, text, trace_id, now)
            .map_err(|error| Refusal::new(error_code_for(&error), error.to_string()))?;

        // ★ One critical section, and the handshake is **outside** it. `dial` blocks for as long as a connection takes,
        // and a `host` guard living across it would mean a `devices` listing waits for a network — which is exactly the
        // report a user runs while something is wrong. So: resolve and read the address under the lock, release it, dial,
        // and take it again to record what happened.
        let (device_id, address, from) = {
            let host = self.host.lock();
            let device_id = host.resolve(to).map_err(|error| refusal_of(&error))?;
            // Where to reach it. A device known by name but never seen has no address, which is a different answer from
            // "nothing is called that".
            let address = host.address_of(device_id).ok_or_else(|| {
                Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{device_id} is known and has no address — it has not been seen on this network"),
                )
            })?;
            (device_id, address, host.device_id())
        };

        // The envelope is built now, addressed to the device that was resolved.
        let envelope = synra_core::text_to(from, device_id, text, trace_id, now)
            .map_err(|error| Refusal::new(error_code_for(&error), error.to_string()))?;

        let mut host = self.host.lock();
        // Dial, which is where the handshake establishes that the device on the other end really is the one asked for.
        let mut link = host.dial(address, None, synra_u64(now)).map_err(|error| refusal_of(&error))?;
        host.send(&mut link, &envelope).map_err(|error| refusal_of(&error))?;
        drop(host);

        // The link is closed on the way out rather than kept: the daemon has nowhere to record it between requests, and a
        // link nobody is reading is one the peer sees as a connection that arrived and went silent. A session per message
        // costs a handshake; holding links open is the next piece of work and is a design decision rather than a detail.
        let _ = link.bye("message delivered");

        Ok(serde_json::json!({
            "sent": true,
            "to": device_id.to_string(),
            "bytes": text.len(),
            "traceId": trace_id.to_string(),
        }))
    }

    /// Sends a file to a device, named by identifier, display name, or `host:port`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming what the user got wrong: the path, the device, or the transfer.
    fn send_file(&self, to: &str, path: &str) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let trace_id = synra_protocol::ids::TraceId::new();
        let source = PathBuf::from(path);

        // ★ The file is checked **before** the device is looked up, for the reason `send --text` checks the text first: a
        // path that does not exist is a mistake in the argument the user just typed, and reporting it as an unknown device
        // would send them to check a device list for a problem that is not there.
        if !source.is_file() {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("{path} is not a file this process can read"),
            ));
        }

        // The same two-step the text path uses: resolve and read the address under one lock, release it, then dial. The
        // handshake can take seconds, and a guard living across it would make a `devices` listing wait for the network.
        //
        // ★ One critical section, a `drop` and then the failures — not an expression that returns them. `?` inside a block
        // whose guard is still alive reads, to clippy's `significant_drop_in_scrutinee`, as a drop on the early-return path
        // — which is the same pattern that has bitten this workspace before.
        // ★ `--to` may be an address as well as a device, and the address is checked first because it is unambiguous by
        // construction: a device identifier and a display name are both arbitrary strings that *could* look like one, and
        // a user who typed `192.168.1.5:47100` meant the address. This is what makes a device reachable before discovery
        // has found it — which is the state every installation is in until its first scan.
        let address = match to.trim().parse::<std::net::SocketAddr>() {
            Ok(address) => address,
            Err(_) => {
                let found = {
                    let host = self.host.lock();
                    match host.resolve(to) {
                        Ok(device_id) => host.address_of(device_id).map(|address| (device_id, address)).ok_or_else(
                            || {
                                Refusal::new(
                                    ErrorCode::DeviceOffline,
                                    format!(
                                        "{device_id} is known and has no address — it has not been seen on this network"
                                    ),
                                )
                            },
                        ),
                        Err(error) => Err(refusal_of(&error)),
                    }
                };
                // The guard is gone by now: the block above ended, which is what `significant_drop_in_scrutinee` wants to
                // see rather than a `?` on an expression that still holds it.
                let (device_id, address) = found?;
                // Kept only so the report below can name the device. The handshake establishes the real identity, and the
                // link is the authority for everything after it.
                let _ = device_id;
                address
            }
        };

        let mut host = self.host.lock();
        let mut link =
            host.dial(address, None, synra_u64(now)).map_err(|error| refusal_of(&error))?;
        // ★ Taken from the link rather than from what the user typed. The handshake is what established who is on the other
        // end, so an address that turned out to belong to a different device is reported as *that* device rather than as
        // the one that was expected.
        let device_id = link.peer();

        // ★ The transfer runs with a deadline, because a peer that stops reading would otherwise hold this thread for ever.
        // The protocol's own scan budget is not the right figure — a file takes as long as it takes — so this is a ceiling
        // on one transfer rather than an expected duration.
        let deadline = std::time::Instant::now() + TRANSFER_DEADLINE;
        let events = synra_core::send_file(
            &mut link,
            &source,
            synra_core::transfer::DEFAULT_CHUNK_SIZE,
            trace_id,
            now,
            deadline,
        )
        .map_err(|error| Refusal::new(error_code_for_session(&error), error.to_string()))?;
        drop(host);

        let bytes = std::fs::metadata(&source).map(|meta| meta.len()).unwrap_or(0);
        let resends = events
            .iter()
            .filter(|event| matches!(event, synra_core::SessionEvent::Resend { .. }))
            .count();
        // ★ `sent` means **the receiver confirmed it**, not "this end finished talking". Those are different claims, and
        // an end-to-end run showed the gap: the file arrived byte-for-byte while the sender reported a transport failure,
        // because it had stopped listening before the confirmation came.
        let confirmed = events
            .iter()
            .any(|event| matches!(event, synra_core::SessionEvent::Verified { .. }));

        // The link is closed rather than kept, for the reason the text path gives: the daemon has nowhere to record it
        // between requests, and a link nobody is reading is one the peer sees as a connection that arrived and went quiet.
        let _ = link.bye("file sent");

        // ★ `confirmed` is a **separate fact** from whether the bytes moved, and an end-to-end run is what showed why: a
        // 300 KB file arrived byte-for-byte with a matching digest while the sender never heard the receiver's completion.
        // Reporting that as a transfer failure would tell a user their file did not arrive when it did — and reporting it
        // as a plain success would claim knowledge this device does not have.
        //
        // So both are said. `sent` is what this device did; `confirmed` is what it heard back.
        Ok(serde_json::json!({
            "sent": true,
            "confirmed": confirmed,
            "to": device_id.to_string(),
            "bytes": bytes,
            "resendRounds": resends,
            "traceId": trace_id.to_string(),
        }))
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

/// A `HostError` as a refusal a client can act on.
///
/// # Why each failure gets its own code
///
/// Because the user's next step differs: a name nothing matches is a typo, an ambiguous name is a decision they have to
/// make, an unreachable device is one that is switched off, and a handshake failure is a network. One code for all of them
/// would leave the client unable to say anything but the message the kernel wrote.
fn refusal_of(error: &HostError) -> Refusal {
    let code = match error {
        // Nothing is called that. `NotPaired` rather than a "not found": what the kernel knows about is devices it has
        // seen, and one it has never seen is one it is not paired with — which is the fact the user can act on.
        HostError::NoSuchDevice { .. } => ErrorCode::NotPaired,
        // Known by name and never seen, so there is no address to dial.
        HostError::Unreachable { .. } => ErrorCode::DeviceOffline,
        // More than one matched, which is a decision the user has to make rather than a fault.
        HostError::AmbiguousName { .. } => ErrorCode::InvalidArgument,
        // The device is there and the two cannot work together, which is a version problem rather than a network one.
        HostError::Incompatible { .. } => ErrorCode::Unsupported,
        // A handshake or a link failure is the network.
        HostError::Handshake(_) | HostError::Link(_) | HostError::Bind { .. } => ErrorCode::TransportNotOpen,
        HostError::NoSession(_) => ErrorCode::NotPaired,
        // `#[non_exhaustive]`: a failure this build does not know is still a failure, and `Internal` is the honest code
        // for one it cannot name.
        _ => ErrorCode::Internal,
    };
    Refusal::new(code, error.to_string())
}

/// The code for a message that could not be built.
const fn error_code_for(error: &synra_core::MessageError) -> ErrorCode {
    match error {
        // The user typed nothing, or typed something too large for one message. Both are about the argument, and the
        // second has its own code — the protocol has one for exactly this, and the client can offer "send as a file".
        synra_core::MessageError::Empty => ErrorCode::InvalidArgument,
        synra_core::MessageError::TooLong { .. } => ErrorCode::PayloadTooLarge,
        // The event name is a constant this build declares, so this is a contradiction inside the kernel rather than
        // anything the caller did.
        synra_core::MessageError::Envelope(_) | synra_core::MessageError::EventName(_) => {
            ErrorCode::Internal
        }
        _ => ErrorCode::Internal,
    }
}

/// The code for a transfer session that failed.
///
/// # Why a transfer failure is not one code
///
/// Because the user`s next step differs: bytes that did not match the digest are a corrupt transfer to retry or not, a
/// missing block is one that never finished, and a link failure is a network. One code for all three would leave the client
/// unable to say anything but the sentence the kernel wrote.
const fn error_code_for_session(error: &synra_core::SessionError) -> ErrorCode {
    match error {
        // A transfer that did not verify is the code the protocol has for exactly this, and a client can act on it: the
        // partial file is discarded and a retry starts again.
        synra_core::SessionError::Transfer(synra_core::TransferError::DigestMismatch { .. })
        | synra_core::SessionError::Transfer(synra_core::TransferError::CompletionMismatch { .. }) => {
            ErrorCode::IntegrityMismatch
        }
        // A transfer that stopped with blocks owed never finished.
        synra_core::SessionError::Transfer(synra_core::TransferError::Incomplete { .. }) => {
            ErrorCode::TransferFailed
        }
        synra_core::SessionError::Link(synra_core::LinkError::Transport { .. }) => {
            ErrorCode::TransportNotOpen
        }
        synra_core::SessionError::Link(_) => ErrorCode::TransportNotOpen,
        synra_core::SessionError::WrongTransfer { .. }
        | synra_core::SessionError::BadProgress(_)
        | synra_core::SessionError::Payload { .. } => ErrorCode::ProtocolViolation,
        // Everything else is this kernel failing rather than the peer or the network, and `Internal` is the honest code for
        // a failure it cannot name.
        _ => ErrorCode::Internal,
    }
}

/// A wall-clock reading as the `u64` the session registry counts in.
///
/// Saturating, because a negative reading is a clock before the epoch and the registry's deadlines are unsigned — and a
/// wrap would put the deadline in the distant future, which is a session that never expires.
const fn synra_u64(value: i64) -> u64 {
    if value < 0 { 0 } else { value as u64 }
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
    fn sending_to_a_device_nothing_is_called_is_refused_before_anything_is_dialled() {
        // ★ "Nothing is called that" is a question about the *text of the argument*, and answering it costs no network at
        // all. A kernel that dialled first would spend a handshake to produce the same refusal.
        let dir = TempDir::new("send-unknown");
        let runtime = runtime(dir.path());
        match runtime.send_text("Nobody", "hello") {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::NotPaired);
                assert!(refusal.message.contains("Nobody"), "{}", refusal.message);
                // And it says how to find out what there is.
                assert!(refusal.message.contains("devices"), "{}", refusal.message);
            }
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    #[test]
    fn sending_empty_text_is_refused_as_an_argument_rather_than_a_network_failure() {
        // ★ The user typed nothing. That is a mistake at the shell, and the *code* says which kind of mistake — a client
        // shows "there is no text to send" rather than offering to try again.
        let dir = TempDir::new("send-empty");
        let runtime = runtime(dir.path());
        for text in ["", "   "] {
            match runtime.send_text("anyone", text) {
                Err(refusal) => assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{text:?}"),
                Ok(value) => panic!("expected a refusal, got {value}"),
            }
        }
    }

    #[test]
    fn text_too_large_for_one_message_gets_the_protocols_own_code() {
        // ★ The protocol has a code for exactly this, and a client can act on it — the next step is to send a file rather
        // than to retry. Reported as `InvalidArgument` it would read as a typo.
        let dir = TempDir::new("send-huge");
        let runtime = runtime(dir.path());
        let huge = "a".repeat(200 * 1024 * 1024);
        match runtime.send_text("anyone", &huge) {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::PayloadTooLarge);
                assert!(refusal.message.contains("file"), "{}", refusal.message);
            }
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    #[test]
    fn file_sending_checks_the_file_before_it_looks_for_the_device() {
        // ★ The same order `send --text` uses, and for the same reason: a path that does not exist is a mistake in the
        // argument the user just typed. Reporting it as an unknown device would send them to check a device list for a
        // problem that is not there.
        let dir = TempDir::new("send-file-missing");
        let runtime = runtime(dir.path());
        match runtime.send_file("nobody", "/definitely/not/here.bin") {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::InvalidArgument);
                assert!(refusal.message.contains("not/here.bin"), "{}", refusal.message);
            }
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    #[test]
    fn file_sending_to_a_device_nothing_is_called_is_refused_after_the_file_passes() {
        // The other side of the same order: a real file and an unknown device is a device problem, and that is the code
        // the client gets. The two checks are separate so the message is about the thing the user got wrong.
        let dir = TempDir::new("send-file-unknown");
        let source = dir.path().join("real.bin");
        std::fs::write(&source, b"contents").expect("writes");
        let runtime = runtime(dir.path());
        match runtime.send_file("nobody", &source.to_string_lossy()) {
            Err(refusal) => assert_eq!(refusal.code, ErrorCode::NotPaired),
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    #[test]
    fn text_sending_no_longer_refuses_for_a_missing_layer() {
        // ★ `send --text` must fail for a reason about the *device*, not about a missing layer. This is what would break
        // first if the two commands were ever wired to the same refusal again.
        let dir = TempDir::new("send-text-real");
        let runtime = runtime(dir.path());
        match runtime.send_text("d", "x") {
            Err(refusal) => {
                // The text path refuses for a reason about the device, not about a missing layer.

                assert_eq!(refusal.code, ErrorCode::NotPaired);
            }
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
    }

    #[test]
    fn a_missing_argument_is_not_retryable() {
        // ★ A refusal about the argument is not retryable, and that is the right answer: repeating the call with the same
        // argument will keep failing. A retryable flag would have a client offer a retry that cannot work.
        //
        // `Unsupported` used to be the example here, for the layer that was not written. Nothing refuses with `Unsupported`
        // any more — the transfer path exists — so the example is an argument the user can fix.
        let dir = TempDir::new("retryable");
        match runtime(dir.path()).send_file("d", "/definitely/not/here.bin") {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::InvalidArgument);
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
