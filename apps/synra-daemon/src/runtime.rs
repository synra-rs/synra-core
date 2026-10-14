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
            "schemaVersion": schema,
            "schemaKnown": synra_store::SynraDb::known_version(),
            "tables": counts,
            // ★ Present rather than omitted, so a client can print it. An absent field would be indistinguishable from
            // an older kernel that does not have the concept. `database` is gone from this list because it is now real.
            "notImplemented": ["session", "discovery"],
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

    fn devices(&self, _include_unpaired: bool) -> Result<serde_json::Value, Refusal> {
        // ★ A refusal rather than an empty list. "No devices" and "I cannot tell you about devices" are different
        // answers, and a client that received an empty list would report that nothing is paired — sending the user to
        // look for a pairing problem in an installation where the code is not written.
        Err(Refusal::new(ErrorCode::Unsupported, MISSING_SESSION_LAYER))
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
        Runtime {
            version: "0.1.0-test".to_owned(),
            data_dir: dir.to_path_buf(),
            plugins_dir: dir.join("plugins"),
            listen_port: 47100,
            discovery_port: 47101,
            started_at_ms: 1_000,
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
        assert!(names.contains(&"session"), "{names:?}");
        assert!(names.contains(&"discovery"), "{names:?}");
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
    fn asking_for_devices_is_refused_rather_than_answered_with_nothing() {
        // ★ "No devices" and "I cannot tell you about devices" are different answers, and only one is true. An empty
        // list would send the user looking for a pairing problem in an installation where the code is not written.
        let dir = TempDir::new("devices");
        match runtime(dir.path()).devices(true) {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::Unsupported);
                assert!(refusal.message.contains("session layer"), "{}", refusal.message);
            }
            Ok(value) => panic!("expected a refusal, got {value}"),
        }
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
                Ok(value) => panic!("expected a refusal, got {value}"),
            }
        }
    }

    #[test]
    fn a_refusal_for_a_missing_layer_is_not_retryable() {
        // ★ `Unsupported` is not retryable, and that is the right answer: repeating the call will keep failing until a
        // new build is installed. A retryable flag would have a client offer a retry that cannot work.
        let dir = TempDir::new("retryable");
        match runtime(dir.path()).devices(false) {
            Err(refusal) => assert!(!refusal.is_retryable()),
            Ok(_) => panic!("expected a refusal"),
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
