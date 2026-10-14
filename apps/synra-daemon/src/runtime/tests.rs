use std::path::{Path, PathBuf};

use synra_control::Kernel;
use synra_core::{Host, Identity};
use synra_protocol::error::ErrorCode;

use super::reports::is_debug_or_trace;
use super::{Runtime, now_ms};

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
    // Read before the identity is moved into the host: the desk derives the verification code from it, and the fixture is
    // the only place a test's device identity comes from.
    let local_id = identity.device_id;
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
        pairing: std::sync::Arc::new(synra_core::pairing::PairingDesk::new(
            local_id,
            synra_protocol::session::SessionTimeouts::default().pairing,
        )),
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

    // ★ The exact contents, and today that is nothing. The list held `session` long after `send --text` and
    // `send --file` both moved real bytes — so it was telling a user that a working feature was missing, which is
    // precisely the failure this assertion exists to catch. An assertion of a *superset* would have passed.
    assert!(names.is_empty(), "a layer that is not missing is named: {names:?}");

    // And the layers that are real are certainly not in it, each having been removed when it started working.
    for built in ["database", "discovery", "session"] {
        assert!(!names.contains(&built), "{built} is listed and is real: {names:?}");
    }
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
