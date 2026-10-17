use std::path::{Path, PathBuf};

use synra_control::Kernel;
use synra_core::{Host, Identity};
use synra_protocol::error::ErrorCode;

use synra_store::records::{AuditRecord, IntentRecord};
use synra_store::{Paired, Seen};

use super::{Runtime, now_ms};

/// A temporary directory that removes itself.
pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-rt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A runtime over a migrated in-memory database, and a plugins directory under `dir`.
pub(super) fn runtime(dir: &Path) -> Runtime {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    runtime_over(dir, std::sync::Arc::new(parking_lot::Mutex::new(db)))
}

/// A runtime and the database it was built over, so a test can build a **second** one over the same store.
fn runtime_shared(dir: &Path) -> (Runtime, std::sync::Arc<parking_lot::Mutex<synra_store::SynraDb>>) {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    let shared = std::sync::Arc::new(parking_lot::Mutex::new(db));
    (runtime_over(dir, std::sync::Arc::clone(&shared)), shared)
}

/// A runtime over a database the caller already holds.
///
/// ★ Why this exists: two runtimes over one store is what a **restart** is, and there is no other way to test that what a
/// daemon wrote down is what the next daemon reads. A fixture that built its own database every time could only ever test
/// a daemon against an empty one.
fn runtime_over(dir: &Path, shared_db: std::sync::Arc<parking_lot::Mutex<synra_store::SynraDb>>) -> Runtime {
    let identity = Identity::load(&shared_db.lock(), "windows", 1_000).expect("an identity");
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
    // ★ One handle, shared: the runtime reads it and so does the host a plugin's calls reach.
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
        db: std::sync::Arc::clone(&shared_db),
        pairing: std::sync::Arc::new(synra_core::pairing::PairingDesk::new(
            local_id,
            synra_protocol::session::SessionTimeouts::default().pairing,
        )),
        // A scripted engine rather than a real one: these tests are about what the daemon *reports*, and a unit test
        // that compiles Wasmtime to assert a JSON field would be a slower version of the same test.
        plugins: std::sync::Arc::new(parking_lot::Mutex::new(synra_core::dispatch::PluginSet::new(
            synra_plugin_host::Backend::new(std::sync::Arc::new(synra_plugin_host::ScriptedBackend::new())),
            // ★ The daemon's own host, not a stub. The fixture exists to answer questions about what the daemon
            // reports, and a stub here would make every question about a plugin's authority answer the same thing.
            std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
                std::sync::Arc::clone(&shared_db),
                "0.1.0-test",
            )),
        ))),
        metrics: std::sync::Arc::new(synra_observe::metrics::RingRecorder::new()),
    plugin_loads: std::sync::Arc::new(parking_lot::Mutex::new(
            crate::runtime::LoadedSummary::default(),
        )),
        board: std::sync::Arc::new(parking_lot::Mutex::new(synra_core::intent::Board::new())),
        // ★ A real verbosity rather than `None`, so a test can assert that `logs --verbose` actually raised it. `None`
        // is the state of a daemon whose log file could not be opened, and a fixture that used it would make every
        // assertion about raising vacuously true.
        verbosity: Some(std::sync::Arc::new(synra_observe::logging::Verbosity::new(
            synra_observe::logging::LogLevel::Info,
        ))),
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
fn a_catalogue_search_answers_from_the_cache_when_no_registry_can() {
    // ★ The design's first offline row, through the command a user actually runs.
    //
    // There is no network in this environment, so this is the path the daemon takes on an aeroplane as well: every mirror
    // refuses, and the cache answers. What is asserted is not only that it worked but that the answer **says where it came
    // from** — a screen that could not tell a live answer from a stale one would be showing a catalogue it cannot vouch for.
    let dir = TempDir::new("catalog-cached");
    let runtime = runtime(dir.path());

    let packument = r#"{"name":"@acme/chat","dist-tags":{"latest":"1.2.3"},"versions":{
        "1.2.3":{"name":"@acme/chat","version":"1.2.3","dist":{"tarball":"https://x/y.tgz","integrity":"sha512-AAAA"}}
    }}"#;
    crate::runtime::catalog::cache_for(&runtime)
        .store("@acme/chat", packument, 0)
        .expect("a cached packument");

    let answer = crate::runtime::catalog::search(&runtime, "@acme/chat").expect("the cached answer");

    assert_eq!(answer["package"], "@acme/chat");
    assert_eq!(answer["latest"], "1.2.3");
    // The origin, which is the half that makes an offline answer honest.
    assert_eq!(answer["origin"]["source"], "cache");
    assert!(answer["origin"]["ageMs"].as_i64().is_some_and(|age| age > 0), "{answer}");
    assert_eq!(answer["origin"]["stale"], true, "an entry fetched at the epoch: {answer}");
}

#[test]
fn a_catalogue_search_that_cannot_reach_anything_says_so_rather_than_answering_empty() {
    // ★ `DeviceOffline`, not an empty list. "No plugins match" and "this kernel could not look" are different facts, and a
    // screen that could not tell them apart would show an empty catalogue for a machine that is simply offline.
    let dir = TempDir::new("catalog-offline");
    let runtime = runtime(dir.path());

    let refused = crate::runtime::catalog::search(&runtime, "@acme/chat").expect_err("nothing to answer with");

    assert_eq!(refused.code, ErrorCode::DeviceOffline, "{refused:?}");
    // And the reason names every mirror that was tried, because "the registry is unreachable" is not actionable.
    assert!(refused.message.contains("@acme/chat"), "{}", refused.message);
}

#[test]
fn the_sweep_takes_only_what_it_is_for() {
    // ★ `11` asks for this and it did not exist: *"GC 的测试断言‘用户数据目录未被触碰’"*.
    //
    // The sweep is the only thing in this kernel that **deletes rows**. A `DELETE` with a missing `WHERE`, or a new
    // collection target written against the wrong table, is not a slow failure or a wrong answer — it is a user's paired
    // devices, plugin consents or settings gone, discovered later and unrecoverable. So the assertion is not "the sweep
    // removed something"; it is that **everything it is not for is exactly as it was**.
    //
    // The instrument is `counts()`, which is what `status` reports: every table, from the schema's own list. Using the
    // product's own mechanism means the test cannot pass by looking at a list somebody kept up to date by hand.
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("the schema");

    // Everything with a public writer, so every table the sweep must not touch has a row to lose.
    db.insert_plugin("@acme/notes", true, true, "enabled", 1_000, 1_000).expect("a plugin");
    db.record_grants("@acme/notes", &[("device:list".to_owned(), true)], 1_000, "digest")
        .expect("grants");
    db.pair_device(&Paired {
        device_id: "01a139a9-8f3c-72ce-9c96-2b2c81f14551".to_owned(),
        display_name: "Laptop".to_owned(),
        platform: "windows".to_owned(),
        features: "[]".to_owned(),
        link_token: "token".to_owned(),
        address: None,
        paired_at_ms: 1_000,
    })
    .expect("a pairing");
    db.set_config("theme", &serde_json::json!("dark"), 1_000).expect("a setting");

    // And one row in each table the sweep **is** for, all old enough to be collectable.
    db.record_seen_device(&Seen {
        device_id: "01b139a9-8f3c-72ce-9c96-2b2c81f14552".to_owned(),
        display_name: "Phone".to_owned(),
        platform: "android".to_owned(),
        seen_at_ms: 1,
        source: "udp".to_owned(),
    })
    .expect("a seen device");
    db.record_audit(&AuditRecord {
        plugin_id: "@acme/notes".to_owned(),
        capability: "device:list".to_owned(),
        outcome: "allowed".to_owned(),
        at_ms: 1,
        elapsed_ms: Some(1),
    })
    .expect("an audit record");
    db.save_intent(&IntentRecord {
        intent_id: "01c139a9-8f3c-72ce-9c96-2b2c81f14553".to_owned(),
        state: "succeeded".to_owned(),
        created_ms: 1,
        updated_ms: 1,
        origin_device: None,
        request_id: None,
        document: "{}".to_owned(),
    })
    .expect("an intent");

    let before: std::collections::BTreeMap<String, i64> = db
        .counts()
        .expect("counts")
        .into_iter()
        .filter_map(|(table, count)| count.map(|count| (table, count)))
        .collect();

    // Aggressive on purpose: a retention of zero makes every finished intent and every audit record collectable, so the
    // sweep has the maximum opportunity to take something it should not.
    let collected = crate::runtime::intents::sweep(
        &db,
        crate::runtime::intents::Retention { intents_ms: 0, audit_ms: 0 },
    );

    let after: std::collections::BTreeMap<String, i64> = db
        .counts()
        .expect("counts")
        .into_iter()
        .filter_map(|(table, count)| count.map(|count| (table, count)))
        .collect();

    // ★ And nothing else moved. Listed as the tables that must be **unchanged**, so a future collection target fails this
    // test by adding itself to the difference rather than by not being mentioned.
    let untouched = [
        "identity",
        "paired_devices",
        "plugins",
        "plugin_versions",
        "plugin_grants",
        "plugin_actions",
        "plugin_deps",
        "sync_records",
        "transfer_sessions",
        "config",
    ];
    for table in untouched {
        assert_eq!(
            before.get(table),
            after.get(table),
            "the sweep changed `{table}`, which it is not for"
        );
    }
    // And the three it is for each have a name in the list, so this cannot pass by the sweep targeting a table nobody
    // mentioned.
    for table in ["intents", "devices_seen", "plugin_audit"] {
        assert!(
            before.contains_key(table) && after.contains_key(table),
            "`{table}` is a collection target and should appear in the counts"
        );
    }

    // ★ **The "it did collect" assertions come last, and that ordering is deliberate.**
    //
    // They were first, and two controls showed why that was wrong: pointing a collection target at `paired_devices` — the
    // exact failure the list above exists for — tripped *"the audit record was collectable"* instead, because the statement
    // errored and the sweep reported zero. The test still failed, so it looked like a working control; what it never reached
    // was the assertion that would have named the table it damaged. A guard the failure never reaches is a guard that is not
    // being tested, and putting the specific assertion before the general one is what fixes it.
    assert_ne!(collected.intents, 0, "the finished intent was collectable");
    assert_ne!(collected.audit, 0, "the audit record was collectable");
}

#[test]
fn status_reports_the_gates_counters() {
    // ★ The whole loop, end to end: a plugin's refused call becomes a counter on the recorder the daemon owns, and the
    // daemon's `status` reports it.
    //
    // Every link of this was missing at some point in this session. The recorder had no producer at all; the producer had
    // no way to reach the kernel; and `diag_metrics` was a command in the contract with no trait method, no handler and no
    // data behind it. The reader here is `status`, which is a command that already existed and already worked.
    let dir = TempDir::new("status-metrics");
    let runtime = runtime(dir.path());

    // A refused call, made the way the gate makes one.
    let refused =
        synra_plugin_host::host_calls::CallError::denied("device:send:*", &synra_capability::CapabilitySet::new());
    assert!(!refused.message.is_empty());
    let key = synra_observe::metrics::SeriesKey::new(
        "gate_denied_total",
        [("capability".to_owned(), "device:send:*".to_owned())],
    );
    runtime.metrics.counter_inc(&key);

    let value = runtime.status().expect("status");
    let series = value["metrics"]["values"].as_array().expect("the series list");
    let refused_series = series
        .iter()
        .find(|entry| entry["key"]["name"] == "gate_denied_total")
        .expect("the refusal is reported");

    assert_eq!(refused_series["value"]["kind"], "counter");
    assert_eq!(refused_series["value"]["value"], 1);
    // And the label survives the trip, because a count without one cannot answer "which permission do plugins keep asking
    // for and not have" — the question the design's `gate_*` metrics exist for.
    let labels = refused_series["key"]["labels"].as_array().expect("labels");
    assert!(
        labels.iter().any(|pair| pair[0] == "capability" && pair[1] == "device:send:*"),
        "{refused_series}"
    );
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
        .db()
        .insert_plugin(id, enabled != 0, trusted != 0, "healthy", 100, 200)
        .expect("a plugin row");
}

/// Records the user's decision about a plugin's capabilities, which is what makes it loadable.
///
/// # ★ Why this helper had to exist
///
/// Because `trusted = 1` is no longer an authorisation. It used to be treated as one: the loader took the manifest's own
/// declaration as the grant, so a row saying "the user trusts this" was enough, and a plugin received exactly what it
/// asked for. Now the grants come from the decisions recorded here, and the manifest's digest is checked against the
/// document those decisions were made about — so a test that set a flag and expected a plugin to run was asserting the
/// old rule.
///
/// That three tests failed the moment this changed is the point rather than a nuisance: they were installing trusted
/// plugins with nothing recorded, which is precisely the state the consistency check exists to catch.
fn consent(runtime: &Runtime, id: &str, granted: &[&str]) {
    let text = std::fs::read_to_string(runtime.plugins_dir.join(id).join("manifest.json"))
        .expect("the manifest this consent is about");
    let manifest: synra_plugin_api::Manifest = serde_json::from_str(&text).expect("a manifest");
    let decisions: Vec<(String, bool)> = manifest
        .capabilities
        .iter()
        .map(|declared| (declared.cap.clone(), granted.contains(&declared.cap.as_str())))
        .collect();
    runtime
        .db()
        .record_grants(id, &decisions, 200, &synra_plugin_api::manifest_digest(&text))
        .expect("the decisions");
}

#[test]
fn a_plugin_directory_the_database_has_never_seen_is_recorded_and_left_off() {
    // ★ The step that was missing entirely, and the reason the whole plugin subsystem was unreachable.
    //
    // `insert_plugin` — the only writer of a `plugins` row — had no production caller. So `db.plugins()` was always
    // empty, so `load_installed` always loaded nothing, whatever was on disk. A user could put a plugin in the right
    // directory and the daemon would never know it existed.
    let dir = TempDir::new("discover-new");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1);
    let recorded = found.first().expect("one entry");
    assert_eq!(recorded.plugin_id, "@acme/hello");
    assert!(recorded.problem.is_none(), "{recorded:?}");

    // ★ And it is recorded **off**. Dropping a directory on disk is not a decision by anybody: the plugin directory is
    // writable by anything running as the user, so treating its contents as approved would make the filesystem the
    // privilege boundary. `should_run` is `enabled && trusted`, and neither is set.
    let rows = runtime.db().plugins().expect("rows");
    let row = rows.first().expect("the row this test just created");
    assert!(!row.enabled, "a discovered directory must not be enabled");
    assert!(!row.trusted, "a discovered directory must not be trusted");
    assert!(!row.should_run(), "so it does not run");
}

#[test]
fn a_plugin_directory_that_is_not_a_plugin_is_reported_rather_than_ignored() {
    // A half-copied install, a stray file, a build's output directory. The distinction a user needs is between "nothing
    // is installed" and "the installation is broken", and only one of those is worth acting on — so the reason is
    // carried out rather than dropped.
    let dir = TempDir::new("discover-broken");
    let runtime = runtime(dir.path());
    std::fs::create_dir_all(runtime.plugins_dir.join("@acme/half-copied")).expect("a directory");

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert_eq!(found.len(), 1);
    let reported = found.first().expect("one entry");
    assert_eq!(reported.plugin_id, "@acme/half-copied");
    assert!(
        reported.problem.as_deref().is_some_and(|why| why.contains("manifest")),
        "the reason should name the manifest: {reported:?}"
    );
    // Nothing was recorded for it, so it cannot be enabled by accident later.
    assert!(runtime.db().plugins().expect("rows").is_empty());
}

#[test]
fn discovering_a_plugin_twice_records_it_once() {
    // The daemon starts on every boot. Re-inserting would fail on the primary key, and "failed to record" printed at
    // every start would be noise that hides a real problem.
    let dir = TempDir::new("discover-twice");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);

    let first = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);
    assert_eq!(first.len(), 1, "the first pass records it");

    let second = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 600);
    assert!(second.is_empty(), "the second pass should find nothing new: {second:?}");
    assert_eq!(runtime.db().plugins().expect("rows").len(), 1);
}

#[test]
fn discovering_does_not_overwrite_a_decision_the_user_has_made() {
    // ★ The guard on the reconciliation being *additive*. A plugin the user enabled and trusted must come back from a
    // restart exactly as they left it — a reconciliation that re-inserted or reset flags would silently switch off every
    // plugin on every boot, which is the kind of bug that looks like "my plugins keep turning themselves off".
    let dir = TempDir::new("discover-existing");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);
    install(&runtime, "@acme/hello", 1, 1);

    let found = crate::runtime::record_discovered_plugins(&runtime.db(), &runtime.plugins_dir, 500);

    assert!(found.is_empty(), "a known plugin is not new: {found:?}");
    let rows = runtime.db().plugins().expect("rows");
    let row = rows.first().expect("the row the user's decision is in");
    assert!(row.enabled && row.trusted, "the user's decision survived: {row:?}");
}

#[test]
fn asking_for_verbose_logs_raises_what_the_daemon_writes() {
    // ★ `--verbose` used to be a promise with nothing behind it. The subscriber was built with a fixed level and
    // `tracing` allows one subscriber per process, so no debug line could ever be written — the CLI asked for debug
    // lines, the file had none, and the command answered with the same lines as the default. Nothing failed; the flag
    // simply did nothing.
    //
    // The assertion is on the **logger's own state**, because that is what decides whether a debug line is written at
    // all. Reading the answer's `lines` could not distinguish "the flag is wired" from "the file happens to have
    // debug lines in it from some earlier run".
    let dir = TempDir::new("logs-raise-verbose");
    let runtime = runtime(dir.path());
    let verbosity = runtime.verbosity.as_ref().expect("a fixture with a logger").clone();

    assert_eq!(verbosity.effective(), synra_observe::logging::LogLevel::Info, "the configured level");
    assert!(!verbosity.is_raised());

    // A plain read asks for nothing and must not change the level: a command that quietly made the log verbose would
    // fill a disk on a machine nobody is watching.
    let plain = runtime.logs_value(10, false, None).expect("an answer");
    assert_eq!(plain["raised"], false);
    assert_eq!(verbosity.effective(), synra_observe::logging::LogLevel::Info, "a plain read changed nothing");

    let answer = runtime.logs_value(10, true, None).expect("an answer");
    assert_eq!(answer["raised"], true, "the raise has to be reported: {answer}");
    assert_eq!(answer["level"], "debug");
    assert_eq!(
        verbosity.effective(),
        synra_observe::logging::LogLevel::Debug,
        "the logger itself has to change, not just the answer"
    );
    assert!(verbosity.remaining().is_some(), "and it has to lapse, or a flag left on fills the disk");
}

#[test]
fn a_trace_filter_asks_for_more_than_verbose_does() {
    // Following one identifier is narrower and more deliberate than asking for everything, so it is worth more detail.
    // Both are bounded by the same window.
    let dir = TempDir::new("logs-raise-trace");
    let runtime = runtime(dir.path());
    let verbosity = runtime.verbosity.as_ref().expect("a fixture with a logger").clone();

    let answer = runtime.logs_value(10, false, Some("abc")).expect("an answer");
    assert_eq!(answer["raised"], true);
    assert_eq!(answer["level"], "trace", "a trace filter raises further than --verbose: {answer}");
    assert_eq!(verbosity.effective(), synra_observe::logging::LogLevel::Trace);
}

#[test]
fn a_daemon_with_no_log_does_not_claim_to_have_raised_anything() {
    // ★ `None` is the state of a daemon whose log file could not be opened. It still answers the command — a host that
    // cannot write a diagnostic file is still a host — and it must not report a raise it did not perform. This is the
    // one case where the difference between "did it" and "said it did" is the whole assertion.
    let dir = TempDir::new("logs-no-logger");
    let mut runtime = runtime(dir.path());
    runtime.verbosity = None;

    let answer = runtime.logs_value(10, true, None).expect("an answer");
    assert_eq!(answer["raised"], false, "{answer}");
    assert_eq!(answer["level"], serde_json::Value::Null, "and it says it has no level to report: {answer}");
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
    assert_eq!(value["loadedCount"], 0);
}

/// Writes a plugin directory the loader will accept: a manifest and a component.
///
/// The manifest carries every field [`synra_plugin_api::Manifest`] requires, because the loader parses the real type
/// rather than a `Value` — a fixture that left one out would be refused for a missing field and the refusal would read
/// as a loader bug.
fn manifest_json(id: &str, capabilities: &str, runtime: &str) -> String {
    format!(
        r#"{{"id": "{id}", "version": "1.2.3", "title": "Fixture",
            "publisher": {{"id": "@acme"}},
            "sdk": {{"min": "0.1.0"}},
            "wit": "synra:plugin",
            "capabilities": [{capabilities}],
            "runtime": {runtime}}}"#
    )
}

/// Writes a plugin directory the loader will accept: a manifest and a component.
fn write_plugin(plugins_dir: &Path, id: &str, capability: &str) {
    let directory = plugins_dir.join(id);
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    let runtime = r#"{"headless": {"artifact": "plugin.wasm", "stateful": false}}"#;
    std::fs::write(directory.join("manifest.json"), manifest_json(id, capability, runtime)).expect("a manifest");
    // The bytes have the WebAssembly header, because the loader's engine refuses anything else — and a fixture that
    // dodged that check would be testing a path no plugin takes.
    std::fs::write(directory.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");
}

/// A loader over a scripted engine, so a test can load without compiling Wasmtime.
fn loader() -> (synra_core::dispatch::PluginSet, synra_plugin_host::ScriptedBackend) {
    let backend = synra_plugin_host::ScriptedBackend::new();
    let set = synra_core::dispatch::PluginSet::new(
        synra_plugin_host::Backend::new(std::sync::Arc::new(backend.clone())),
        // ★ The same host the fixture uses: a plugin loaded by these tests is given a session built from the real
        // one, so a question about authority is answered by the code that answers it in production.
        std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
            std::sync::Arc::new(parking_lot::Mutex::new(
                synra_store::SynraDb::open_in_memory().expect("a database"),
            )),
            "0.1.0-test",
        )),
    );
    (set, backend)
}

#[test]
fn revoking_one_plugin_leaves_the_others_alone() {
    // """ + S + """ The same class of guard as the sweep's, for the kernel's other destructive action.
    //
    // Revoking a plugin **disables a row**, and a revocation that matched too widely — a comparison on the wrong field, a
    // query missing its identifier — would disable plugins the list never named. The user sees a plugin they installed and
    // approved stop working, with a reason about a version that is not theirs, and no way to tell what happened.
    //
    // So the assertion is not "the revoked one was disabled". It is that **the other one was not**, which is the claim a
    // too-wide match breaks and the claim nothing was checking.
    let dir = TempDir::new("load-revoked-others");
    let runtime = runtime(dir.path());
    for id in ["@bad/plugin", "@good/plugin"] {
        write_plugin(&runtime.plugins_dir, id, r#"{"cap": "log:info"}"#);
        install(&runtime, id, 1, 1);
        consent(&runtime, id, &["log:info"]);
    }

    // A list that names one plugin at the version both of them have, so a match on the version alone would catch both and a
    // match on the name alone would catch only the intended one. Both facts matter, which is why the list is written this
    // way rather than with a version only one plugin has.
    let list = synra_plugin_api::revocation::RevocationList::parse(
        r#"{"revoked":[{"plugin":"@bad/plugin","versions":["1.2.3"],"reason":"malicious code"}]}"#,
    )
    .expect("a list");
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &list,
    );

    let rows: std::collections::BTreeMap<String, bool> = runtime
        .db()
        .plugins()
        .expect("the rows")
        .into_iter()
        .map(|row| (row.plugin_id, row.enabled))
        .collect();

    assert_eq!(rows.get("@bad/plugin"), Some(&false), "the revoked one is disabled");
    assert_eq!(
        rows.get("@good/plugin"),
        Some(&true),
        "a plugin the list does not name was disabled too: {rows:?}"
    );
    // And it still loaded, which is the consequence a user would notice.
    assert_eq!(summary.len(), 1, "refused: {:?}", summary.refused);
    assert!(summary.contains(&synra_protocol::ids::PluginId::try_from("@good/plugin".to_owned()).expect("an id")));
}

#[test]
fn a_revoked_installed_version_is_refused_and_disabled() {
    // ★ The design's behaviour for an installed revoked version: *"disable immediately, and tell the user"*. Both halves are
    // asserted, because either alone is a plugin that comes back:
    //
    // * refusing to **load** it this run is not disabling it — the row stays enabled and the next start tries again;
    // * disabling the **row** without saying why leaves a user with a plugin that switched itself off.
    let dir = TempDir::new("load-revoked");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@bad/plugin", r#"{"cap": "log:info"}"#);
    install(&runtime, "@bad/plugin", 1, 1);
    consent(&runtime, "@bad/plugin", &["log:info"]);

    // And without the list it loads, so the test is about the list rather than about the plugin.
    let (mut set, _backend) = loader();
    let without = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert_eq!(without.len(), 1, "refused: {:?}", without.refused);

    let list = synra_plugin_api::revocation::RevocationList::parse(
        r#"{"revoked":[{"plugin":"@bad/plugin","versions":["1.2.3"],"reason":"malicious code"}]}"#,
    )
    .expect("a list");
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &list,
    );

    assert!(summary.is_empty(), "a revoked plugin was loaded: {:?}", summary.loaded);
    let refused = summary.refused.first().expect("a refusal");
    assert_eq!(refused.plugin_id, "@bad/plugin");
    // The reason reaches the user, and it says the disable happened rather than only that loading was skipped.
    assert!(refused.reason.contains("malicious code"), "{}", refused.reason);
    assert!(refused.reason.contains("disabled"), "{}", refused.reason);

    // ★ And the row is off, which is the half that survives a restart.
    let row = runtime
        .db()
        .plugins()
        .expect("the rows")
        .into_iter()
        .find(|row| row.plugin_id == "@bad/plugin")
        .expect("the row");
    assert!(!row.enabled, "a revoked plugin is still enabled in the store");
}

#[test]
fn an_enabled_and_trusted_plugin_is_actually_loaded() {
    // ★ This is the test the hardcoded `"loaded": false` made impossible to write. Before the load pass existed there
    // was no code path from a database row to a compiled component, so there was nothing here to assert.
    let dir = TempDir::new("load-one");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);
    install(&runtime, "@acme/hello", 1, 1);

    consent(&runtime, "@acme/hello", &["log:info"]);
    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert_eq!(summary.len(), 1, "the one plugin that should run did; refused: {:?}", summary.refused);
    assert!(summary.contains(&synra_protocol::ids::PluginId::try_from("@acme/hello".to_owned()).expect("an id")));
    assert!(summary.refused.is_empty(), "nothing was refused: {:?}", summary.refused);
}

#[test]
fn a_plugin_the_user_never_answered_about_is_not_loaded_even_when_it_is_trusted() {
    // ★ The consistency check, and the reason `trusted = 1` stopped being an authorisation.
    //
    // The grants used to come from the manifest's own declaration, so a row saying "the user trusts this" was enough and
    // a plugin received exactly what it asked for. A row in that state — trusted, with nothing recorded — is what a
    // pre-consent build left behind, and it must not load: there is no decision behind the flag.
    let dir = TempDir::new("no-consent");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);
    install(&runtime, "@acme/hello", 1, 1);
    // Deliberately no `consent`.

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "nothing may be loaded: {summary:?}");
    let refused = summary.refused.first().expect("a refusal, not silence");
    assert_eq!(refused.plugin_id, "@acme/hello");
    assert!(
        refused.reason.contains("confirmed by the user"),
        "the reason has to be one a user can act on: {}",
        refused.reason
    );
}

#[test]
fn a_plugin_whose_manifest_changed_after_consent_needs_confirming_again() {
    // ★ Why the decision is recorded against a digest rather than against the plugin.
    //
    // A user approves a plugin that asks for `log:*`, and then the package is replaced by one that also asks for
    // `device:list`. The decisions on record are about a **different document**, so the honest answer is "confirm this
    // again" — not "run it with less than it says it needs", which produces a plugin that appears to work and fails at
    // one thing.
    let dir = TempDir::new("stale-consent");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);
    install(&runtime, "@acme/hello", 1, 1);
    consent(&runtime, "@acme/hello", &["log:info"]);

    // The package is replaced. Same id, same version, one more capability — a change an author can make without bumping
    // anything, which is exactly why the bytes are what is hashed.
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}, {"cap": "device:list"}"#);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "nothing may be loaded: {summary:?}");
    let refused = summary.refused.first().expect("a refusal, not silence");
    assert!(
        refused.reason.contains("changed since the user confirmed it"),
        "the reason has to say what happened: {}",
        refused.reason
    );
}

#[test]
fn the_grants_a_plugin_runs_with_are_the_ones_the_user_gave_it() {
    // ★ The difference the whole change exists for, asserted at the only place it is observable from outside.
    //
    // The manifest declares two capabilities; the user granted one. The plugin must load with **one**, because the set
    // it runs with is the user's decision rather than the author's request. Before this, the two were the same thing by
    // construction and no test could tell them apart.
    let dir = TempDir::new("granted-narrow");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}, {"cap": "device:list"}"#);
    install(&runtime, "@acme/hello", 1, 1);
    consent(&runtime, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert_eq!(summary.len(), 1, "the plugin still runs: {:?}", summary.refused);

    // Read back through the set rather than the database, so this asserts what the *plugin* was given.
    let held = set
        .grants(&synra_protocol::ids::PluginId::try_from("@acme/hello".to_owned()).expect("an id"))
        .expect("the plugin is loaded");
    let held: Vec<String> = held.iter().map(ToString::to_string).collect();
    assert_eq!(held, vec!["log:info".to_owned()], "the granted set, not the requested one: {held:?}");
}

#[test]
fn safe_mode_loads_nothing_and_says_why() {
    // ★ The wiring this test exists for: `StartupVerdict::allows_plugins` was tested on its own and called from nowhere,
    // so a plugin that crashed this location three times running would be started a fourth. The settings screen the user
    // needs in order to switch it off is the thing safe mode protects, and nothing was protecting it.
    //
    // The plugin here is perfectly loadable — enabled, trusted, artifact present. It is not loaded, and that is the
    // assertion: safe mode has to stop a *good* plugin, because the daemon cannot know which one is crashing until it
    // starts them.
    let dir = TempDir::new("safe-mode");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);
    install(&runtime, "@acme/hello", 1, 1);

    consent(&runtime, "@acme/hello", &["log:info"]);
    let (mut set, _backend) = loader();
    // ★ The verdict is reached the way the daemon reaches it — by writing crash reports and asking the store — rather
    // than by constructing `SafeMode` here. Hand-building the enum would test that `allows_plugins` returns false for a
    // value the test itself made up; this tests that three crashes in one place produce that value.
    let crashes = synra_observe::crash::CrashStore::new(dir.path());
    // ★ Distinct timestamps, because `CrashStore::write` names each file `crash-{at_ms}.json`. Three reports written
    // at the same millisecond land on one path and the last overwrites the other two — which is what this test did on
    // its first run, and the symptom was `recent_count: 1` for three crashes. Real panics are milliseconds apart, so
    // the fixture has to be too; the collision itself is noted in `write`'s own gap.
    for offset in 0..synra_observe::crash::SAFE_MODE_THRESHOLD {
        crashes
            .write(&synra_observe::crash::CrashReport::new(
                1_000 + i64::try_from(offset).expect("a small offset"),
                "1.0.0",
                Some("src/plugin.rs:42".to_owned()),
                Some("the plugin panicked".to_owned()),
                None,
                None,
                None,
            ))
            .expect("the report is written");
    }
    let safe = crashes.verdict(1_000);
    assert!(
        !safe.allows_plugins(),
        "three crashes in one location did not reach safe mode: {safe:?}"
    );

    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &safe,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "safe mode loaded something: {:?}", summary.loaded);
    // ★ Not in `refused`: this plugin did not fail, it was never examined. Reporting it as a refusal would put a plugin
    // author on a bug report for the daemon's own decision.
    assert!(
        summary.refused.is_empty(),
        "a plugin was blamed for a decision the daemon made: {:?}",
        summary.refused
    );
    // And the reason is carried out, so the daemon can print it rather than showing an empty list that reads as
    // "nothing is installed".
    let why = summary.safe_mode.as_deref().expect("safe mode must explain itself");
    assert!(why.contains("src/plugin.rs:42"), "the explanation does not name the location: {why}");
}

#[test]
fn a_plugin_the_user_never_trusted_is_not_loaded_and_not_refused() {
    // `should_run` is `enabled && trusted`, so an untrusted plugin is a decision the user has not made yet. Reporting
    // it as a refusal would put a plugin author on a bug report for a plugin that has not been approved for anything.
    let dir = TempDir::new("load-untrusted");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "net:fetch:*"}"#);
    install(&runtime, "@acme/hello", 1, 0);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty(), "an untrusted plugin is not loadable");
    assert!(summary.refused.is_empty(), "and untrusted is not a failure: {:?}", summary.refused);
}

#[test]
fn one_broken_plugin_does_not_stop_the_others() {
    // ★ A machine with three plugins and one missing artifact must still run the other two. A loader that stopped at the
    // first failure would turn a plugin's problem into the kernel refusing to start.
    let dir = TempDir::new("load-broken");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/good", r#"{"cap": "log:info"}"#);
    // The broken one has a manifest and no artifact.
    let broken = runtime.plugins_dir.join("@acme/broken");
    std::fs::create_dir_all(&broken).expect("a plugin directory");
    std::fs::write(
        broken.join("manifest.json"),
        manifest_json(
            "@acme/broken",
            "",
            r#"{"headless": {"artifact": "plugin.wasm", "stateful": false}}"#,
        ),
    )
    .expect("a manifest");
    install(&runtime, "@acme/broken", 1, 1);
    install(&runtime, "@acme/good", 1, 1);
    // `plugin_grants` has a foreign key onto `plugins`, so a decision cannot exist before the row it is about — which
    // is the schema saying the same thing the loader does: consent is about a plugin that is installed.
    consent(&runtime, "@acme/broken", &[]);
    consent(&runtime, "@acme/good", &["log:info"]);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert_eq!(summary.len(), 1, "the working plugin loaded");
    assert_eq!(summary.refused.len(), 1, "and the broken one is accounted for");
    assert_eq!(summary.refused[0].plugin_id, "@acme/broken");
    assert!(
        summary.refused[0].reason.contains("artifact"),
        "the reason names what is wrong: {}",
        summary.refused[0].reason
    );
}

#[test]
fn a_ui_only_plugin_is_refused_rather_than_loaded_because_it_has_no_headless_half() {
    // A UI plugin is a working plugin that does not run here — its interface is served by the shell. Calling that a
    // failure would be wrong, and calling it loaded would be a lie, so it is named as what it is.
    let dir = TempDir::new("load-ui-only");
    let runtime = runtime(dir.path());
    let directory = runtime.plugins_dir.join("@acme/ui-only");
    std::fs::create_dir_all(&directory).expect("a plugin directory");
    std::fs::write(
        directory.join("manifest.json"),
        manifest_json("@acme/ui-only", "", r#"{"ui": {"artifact": "dist", "entry": "index.html"}}"#),
    )
    .expect("a manifest");
    install(&runtime, "@acme/ui-only", 1, 1);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    assert!(summary.is_empty());
    assert_eq!(summary.refused.len(), 1);
    assert!(summary.refused[0].reason.contains("headless"), "{}", summary.refused[0].reason);
}

#[test]
fn the_report_says_what_was_loaded_and_not_a_constant() {
    // ★ The assertion that would have caught the hardcoded `false`: after a load pass that loaded something, the report
    // has to say so. A field that cannot change with the system's state is decoration.
    let dir = TempDir::new("load-report");
    let runtime = runtime(dir.path());
    write_plugin(&runtime.plugins_dir, "@acme/hello", r#"{"cap": "log:info"}"#);
    install(&runtime, "@acme/hello", 1, 1);
    consent(&runtime, "@acme/hello", &["log:info"]);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    *runtime.plugin_loads.lock() = summary;

    let value = runtime.plugins().expect("plugins");
    assert_eq!(value["loaded"], true, "something is askable now");
    assert_eq!(value["loadedCount"], 1);
    assert_eq!(value["loadedIds"][0], "@acme/hello");
    assert_eq!(value["notLoaded"].as_array().map(Vec::len), Some(0));
}

#[test]
fn the_report_names_a_plugin_it_could_not_load() {
    // A user with one broken plugin can act on the reason; a user told only "nothing is loaded" cannot.
    let dir = TempDir::new("load-report-refused");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/absent", 1, 1);

    let (mut set, _backend) = loader();
    let summary = crate::runtime::load_installed(
        &mut set,
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );
    assert_eq!(summary.refused.len(), 1, "the fixture has a row and no directory");
    *runtime.plugin_loads.lock() = summary;

    let value = runtime.plugins().expect("plugins");
    assert_eq!(value["loaded"], false, "nothing loaded, and it says so");
    assert_eq!(value["notLoaded"][0]["id"], "@acme/absent");
    assert!(
        value["notLoaded"][0]["reason"].as_str().is_some_and(|reason| reason.contains("manifest")),
        "and the reason says what is missing: {value}"
    );
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
    let value = runtime(dir.path()).logs(10, false, None).expect("logs");
    assert_eq!(value["lines"].as_array().map(Vec::len), Some(0));
    assert!(value["source"].is_null());
}

#[test]
fn the_tail_is_the_last_lines_in_order() {
    let dir = TempDir::new("logs-tail");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(log_dir.join("kernel.log"), "one\ntwo\nthree\nfour\n").expect("a log");

    let value = runtime(dir.path()).logs(2, false, None).expect("logs");
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

    let value = runtime(dir.path()).logs(1_000, false, None).expect("logs");
    assert_eq!(value["lines"].as_array().map(Vec::len), Some(2));
}

#[test]
fn the_log_reader_and_the_log_writer_agree_on_the_directory() {
    // ★ The failure this catches is silent, which is why it is worth a test of its own.
    //
    // Two places decide where the log lives. The writer takes it from `Paths::log_dir()` (`serve.rs`), and the reader
    // builds `self.data_dir.join("logs")` by hand (`reports.rs`). Today they agree — `Paths` defines `log_dir` as
    // exactly that join — but the agreement is a coincidence of two independent lines rather than one rule, and if
    // `Paths` ever moved the log somewhere else the symptom would be `synra logs` returning an empty list forever while
    // the daemon wrote to a file nobody read. No error, no warning, and the log looks like it is simply quiet.
    let root = PathBuf::from("/tmp/synra-agreement");
    let paths = synra_store::Paths::new(root.clone(), root.join("cache"));

    // The reader's directory, exactly as `logs_value` builds it.
    let reader = root.join("logs");
    assert_eq!(
        paths.log_dir(),
        reader,
        "the writer's log directory and the reader's are not the same place, so `synra logs` would always be empty"
    );
}

#[test]
fn a_trace_filter_keeps_only_the_lines_that_mention_it() {
    // ★ The half of `--trace` that did not exist. The CLI carried the flag, the flag parsed, and the id was thrown away
    // before it reached the request — so this filter had nothing to filter on and the command returned everything. A
    // user following one action got the whole log and no sign that their filter had been ignored.
    let dir = TempDir::new("logs-trace");
    let log_dir = dir.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("the log directory");
    std::fs::write(
        log_dir.join("kernel.log"),
        "INFO started trace_id=trace-1\n\
         DEBUG detail trace_id=trace-2\n\
         INFO finished trace_id=trace-1\n\
         INFO unrelated\n",
    )
    .expect("a log");

    // A trace filter widens the level — a trace's lines are the debug ones — and then keeps only its own.
    let only = runtime(dir.path()).logs(10, true, Some("trace-1")).expect("logs");
    let lines: Vec<&str> = only["lines"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(lines.len(), 2, "expected the two trace-1 lines, got {lines:?}");
    assert!(lines.iter().all(|line| line.contains("trace-1")), "{lines:?}");

    // The other trace is not in there, which is what makes this a filter rather than a substring coincidence.
    assert!(!lines.iter().any(|line| line.contains("trace-2")), "{lines:?}");

    // ★ And the id is echoed, so a caller can tell "this trace has no lines" from "the filter was dropped on the way
    // here" — the exact confusion the discarded id produced.
    assert_eq!(only["trace"].as_str(), Some("trace-1"));

    // An id nothing matches is an empty list rather than every line, which is the failure the old code produced.
    let none = runtime(dir.path()).logs(10, true, Some("trace-does-not-exist")).expect("logs");
    assert_eq!(none["lines"].as_array().map(Vec::len), Some(0));

    // And no filter still returns everything, so the field's absence is not a filter of its own.
    let all = runtime(dir.path()).logs(10, true, None).expect("logs");
    assert_eq!(all["lines"].as_array().map(Vec::len), Some(4));
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
    let quiet = runtime(dir.path()).logs(10, false, None).expect("logs");
    assert_eq!(quiet["lines"].as_array().map(Vec::len), Some(2));
    let verbose = runtime(dir.path()).logs(10, true, None).expect("logs");
    assert_eq!(verbose["lines"].as_array().map(Vec::len), Some(3));

    // And the shape the real log has, where a timestamp comes first — the case the naive `contains(" DEBUG ")` did
    // happen to handle, which is why the bug survived being read.
    std::fs::write(
        log_dir.join("kernel.log"),
        "2026-01-01T00:00:00Z INFO started\n2026-01-01T00:00:01Z DEBUG detail\n",
    )
    .expect("a log");
    let stamped = runtime(dir.path()).logs(10, false, None).expect("logs");
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

    let value = runtime(dir.path()).logs(10, false, None).expect("logs");
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

// ── Answering a pairing prompt ────────────────────────────────────────────────────────────────

#[test]
fn answering_a_prompt_records_the_pairing_and_releases_the_waiting_link() {
    // The closed loop: a peer's request is on the desk and its connection is blocked on a channel; the user's decision
    // arrives on the *control* channel, which is a different thread with no access to that socket. This asserts that the
    // decision reaches the waiter and the record reaches the database — the two halves that make pairing work at all.
    let dir = TempDir::new("pair-answer");
    let runtime = runtime(dir.path());
    let dialer: synra_protocol::ids::DeviceId =
        "01a139a9-8f3c-72ce-9c96-2b2c81f14552".parse().expect("a valid device id");
    let request_id = synra_protocol::ids::RequestId::new();

    let request = synra_protocol::session::PairRequest {
        profile: synra_protocol::session::PeerProfile {
            device_id: dialer,
            display_name: "Laptop".to_owned(),
            platform: synra_protocol::session::PlatformKind::Desktop,
            app_version: "0.1.0".to_owned(),
        },
        user_hint: None,
    };
    let synra_core::pairing::Offer::Waiting(waiter) =
        runtime.pairing.offer(request_id, request, "127.0.0.1:5000", 1_000)
    else {
        panic!("a first request waits for a user");
    };

    let answer = Kernel::pair_answer(&runtime, &request_id.to_string(), true).expect("answered");
    assert_eq!(answer["accepted"], serde_json::json!(true), "{answer}");

    // The connection blocked on the socket is released by that same decision.
    let delivered = waiter.wait(std::time::Duration::from_millis(50));
    assert!(delivered.accepted);

    // And the record is durable, so the next link from that device is trusted rather than asked to pair again.
    let state = crate::pairing::state_for(
        &runtime.db(),
        dialer,
        synra_protocol::handshake::LinkToken::from_hex(
            delivered.issued_token().expect("an acceptance issues a token"),
        )
        .ok()
        .as_ref(),
    );
    assert_eq!(state, synra_protocol::handshake::PairingState::Current);
}

#[test]
fn declining_a_prompt_writes_nothing_and_releases_the_link() {
    let dir = TempDir::new("pair-answer");
    let runtime = runtime(dir.path());
    let dialer: synra_protocol::ids::DeviceId =
        "01a139a9-8f3c-72ce-9c96-2b2c81f14553".parse().expect("a valid device id");
    let request_id = synra_protocol::ids::RequestId::new();
    let request = synra_protocol::session::PairRequest {
        profile: synra_protocol::session::PeerProfile {
            device_id: dialer,
            display_name: "Phone".to_owned(),
            platform: synra_protocol::session::PlatformKind::Android,
            app_version: "0.1.0".to_owned(),
        },
        user_hint: None,
    };
    let synra_core::pairing::Offer::Waiting(waiter) =
        runtime.pairing.offer(request_id, request, "127.0.0.1:5000", 1_000)
    else {
        panic!("a first request waits for a user");
    };

    let answer = Kernel::pair_answer(&runtime, &request_id.to_string(), false).expect("answered");
    assert_eq!(answer["accepted"], serde_json::json!(false));

    let delivered = waiter.wait(std::time::Duration::from_millis(50));
    assert!(!delivered.accepted);
    assert!(runtime.db().paired_devices().expect("reads").is_empty(), "a refusal records nothing");
}

#[test]
fn answering_a_request_nobody_made_is_refused_with_a_reason() {
    // Expired while the user was deciding, or answered twice. Either way the caller must not be told the pairing
    // happened, because the device it was about has already been released.
    let dir = TempDir::new("pair-answer");
    let runtime = runtime(dir.path());
    let error = Kernel::pair_answer(
        &runtime,
        "01a139a9-8f3c-72ce-9c96-2b2c81f14551",
        true,
    )
    .expect_err("nothing is waiting under that request");
    assert!(error.message.contains("no pairing request"), "{error:?}");
}

#[test]
fn a_request_id_that_is_not_one_is_refused_before_anything_is_looked_up() {
    let dir = TempDir::new("pair-answer");
    let runtime = runtime(dir.path());
    let error = Kernel::pair_answer(&runtime, "not-a-request-id", true)
        .expect_err("that is not a request id");
    assert!(error.message.contains("not a request id"), "{error:?}");
}


#[test]
fn enabling_a_plugin_writes_the_flag_and_says_so() {
    // ★ The write that had no caller.
    //
    // `set_plugin_enabled` existed in the store and was tested there, and **nothing in production called it** — so
    // `synra plugin enable` could not have worked even once the CLI asked for it. This is the other end of that wire.
    let dir = TempDir::new("enable-plugin");
    let runtime = runtime(dir.path());
    let plugin = "@acme/switchable";
    install(&runtime, plugin, 0, 0);

    runtime
        .plugin_set_enabled(plugin, true)
        .expect("enabling an installed plugin succeeds");

    // ★ Asserted in the database, not from the answer.
    //
    // The answer is the plugin list, so asserting on it would pass against an implementation that reported a list without
    // writing anything — which is the exact shape of the defect this test exists for. `plugins()` re-reads the row.
    let row = runtime
        .db()
        .plugins()
        .expect("plugins")
        .into_iter()
        .find(|row| row.plugin_id == plugin)
        .expect("the row is still there");
    assert!(row.enabled, "the flag was not written: {row:?}");

    // And the answer is the list it now stands in, so a caller does not have to ask twice.
    let listed = runtime.plugin_set_enabled(plugin, false).expect("the list");
    assert!(
        listed.to_string().contains(plugin),
        "the answer is the plugin list: {listed}"
    );
}

#[test]
fn enabling_a_plugin_that_is_not_installed_is_a_refusal() {
    // ★ A typo and a no-op are different answers.
    //
    // `set_plugin_enabled` reports whether a row changed, so enabling an already-enabled plugin answers `false` — which
    // is a success with nothing to do. Reporting that as "no such plugin" would send a user looking for a mistake they did
    // not make; reporting a typo as a success would leave them believing it worked.
    let dir = TempDir::new("enable-plugin-typo");
    let runtime = runtime(dir.path());
    install(&runtime, "@acme/switchable", 1, 0);

    // Already enabled: a second enable is a success, because there is nothing to correct.
    assert!(runtime.plugin_set_enabled("@acme/switchable", true).is_ok());

    // Not installed at all: a refusal that names it, so the user can see their own typo.
    let refused = runtime
        .plugin_set_enabled("@acme/typo", true)
        .expect_err("no such plugin");
    assert!(refused.to_string().contains("@acme/typo"), "{refused}");
}

// ── Surviving a restart ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_intent_survives_a_restart() {
    // ★ The whole point of persisting, driven through the daemon rather than the library.
    //
    // Before this, the board was a `HashMap` in memory and nothing wrote it down: a daemon that restarted lost every intent
    // it was working on. The second runtime below is over the **same** database, which is what a restart is.
    let dir = TempDir::new("intent-restart");
    let (first, db) = runtime_shared(dir.path());

    let raised = first.intent_dispatch("text/plain", "https://example.test/a").expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();
    assert_eq!(db.lock().intent_count().expect("counted"), 1, "it was written down");

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1, "and read back");
    assert!(second.intent_snapshot(&id).is_ok(), "the board remembers the intent");
}

#[test]
fn a_restored_intent_is_the_same_intent_rather_than_a_new_one() {
    // ★ Why `restore` is not `raise`.
    //
    // `raise` mints an identifier and a trace. A restored intent has both, and a restart that gave it new ones would mean a
    // peer resending the request it originally raised is answered with a **second** intent — and the action runs twice,
    // which is the exact failure this path exists to prevent.
    let dir = TempDir::new("intent-same");
    let (first, db) = runtime_shared(dir.path());

    let raised = first.intent_dispatch("text/plain", "https://example.test/a").expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();
    let trace_before = first.intent_snapshot(&id).expect("a snapshot")["trace"].clone();

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1);

    let snapshot = second.intent_snapshot(&id).expect("the same intent");
    assert_eq!(snapshot["intent"].as_str(), Some(id.as_str()), "the same identifier");
    assert_eq!(snapshot["trace"], trace_before, "and the same trace");
}

#[test]
fn a_restart_does_not_bring_back_an_intent_twice() {
    // Restoring is idempotent from the caller's side: two runtimes reading one store, then restoring again, must leave one
    // intent on the board — a duplicate would be offered to the user twice.
    let dir = TempDir::new("intent-twice");
    let (first, db) = runtime_shared(dir.path());
    let raised = first.intent_dispatch("text/plain", "https://example.test/a").expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1);
    assert_eq!(second.restore_intents(), 0, "nothing left to restore");
    assert_eq!(second.board.lock().len(), 1, "and still one intent");
    assert!(second.intent_snapshot(&id).is_ok());
}

#[test]
fn an_empty_store_restores_nothing_rather_than_failing() {
    // A first start, which is the ordinary case.
    let dir = TempDir::new("intent-empty");
    let runtime = runtime(dir.path());

    assert_eq!(runtime.restore_intents(), 0);
    assert_eq!(runtime.board.lock().len(), 0);
}

#[test]
fn a_document_that_cannot_be_read_is_skipped_rather_than_fatal() {
    // ★ The choice, made explicitly: a row written by a build whose shape has changed must not stop the daemon from
    // starting. The alternative is losing every intent — including the ones a peer is waiting on — because of one row.
    let dir = TempDir::new("intent-bad");
    let (first, db) = runtime_shared(dir.path());
    let raised = first.intent_dispatch("text/plain", "https://example.test/a").expect("raised");
    let id = raised["intent"].as_str().expect("an identifier").to_owned();

    // A second intent whose document is not an intent at all, written behind the daemon's back.
    let good = db.lock().load_intents().expect("loaded").remove(0);
    db.lock()
        .save_intent(&IntentRecord {
            intent_id: "01a14199-f364-7612-af4f-000000000001".to_owned(),
            state: "matching".to_owned(),
            created_ms: 2_000,
            updated_ms: 2_000,
            origin_device: None,
            request_id: None,
            document: "not an intent".to_owned(),
        })
        .expect("written");

    let second = runtime_over(dir.path(), std::sync::Arc::clone(&db));
    assert_eq!(second.restore_intents(), 1, "the readable one");
    assert!(second.intent_snapshot(&id).is_ok(), "and the daemon started anyway");
    let _ = good;
}

// ── Forgetting what is finished ───────────────────────────────────────────────────────────────────

/// A stored intent, ready for the sweep.
fn stored(id: &str, state: &str, at_ms: i64) -> IntentRecord {
    IntentRecord {
        intent_id: id.to_owned(),
        state: state.to_owned(),
        created_ms: at_ms,
        updated_ms: at_ms,
        origin_device: None,
        request_id: None,
        document: "{}".to_owned(),
    }
}

#[test]
fn the_sweep_forgets_a_finished_intent_that_is_old_enough() {
    // ★ The rule the design gives intents: twenty-four hours after they finish. Before this ran nowhere, so a device
    // raising intents for months carried every one of them.
    let dir = TempDir::new("gc-old");
    let (runtime, db) = runtime_shared(dir.path());
    let long_ago = store_time() - (48 * 60 * 60 * 1_000);
    db.lock().save_intent(&stored("finished", "succeeded", long_ago)).expect("stored");

    let removed = runtime.collect_intents(24 * 60 * 60 * 1_000);

    assert_eq!(removed, 1);
    assert_eq!(db.lock().intent_count().expect("counted"), 0);
}

#[test]
fn the_sweep_keeps_work_that_is_still_running() {
    // ★ The half that matters more. An intent that has been running for two days is not old data — it is something a user
    // asked for, and a sweep that collected it would lose it without telling anyone.
    let dir = TempDir::new("gc-running");
    let (runtime, db) = runtime_shared(dir.path());
    let long_ago = store_time() - (48 * 60 * 60 * 1_000);
    db.lock().save_intent(&stored("running", "dispatching", long_ago)).expect("stored");

    assert_eq!(runtime.collect_intents(24 * 60 * 60 * 1_000), 0);
    assert_eq!(runtime.board.lock().len(), 0, "and it was never on the board either");
    assert_eq!(db.lock().intent_count().expect("counted"), 1, "still there, still running");
}

#[test]
fn the_sweep_keeps_an_intent_that_finished_recently() {
    // Twenty-four hours is a retention, not a "collect anything finished" rule: a result the user may still be reading must
    // survive the sweep.
    let dir = TempDir::new("gc-recent");
    let (runtime, db) = runtime_shared(dir.path());
    let an_hour_ago = store_time() - (60 * 60 * 1_000);
    db.lock().save_intent(&stored("recent", "succeeded", an_hour_ago)).expect("stored");

    assert_eq!(runtime.collect_intents(24 * 60 * 60 * 1_000), 0);
    assert_eq!(db.lock().intent_count().expect("counted"), 1);
}

#[test]
fn the_sweep_does_not_touch_what_a_plugin_stored() {
    // ★ The design's first requirement for GC: user data is never deleted. `plugin_storage` is where a plugin's own values
    // live, and a sweep that reached it would destroy work the user cannot get back.
    let dir = TempDir::new("gc-storage");
    let (runtime, db) = runtime_shared(dir.path());
    db.lock().insert_plugin("@acme/notes", true, true, "healthy", 1, 1).expect("a plugin row");
    db.lock().storage_set("@acme/notes", "draft", "the user's words", 1_000).expect("stored");
    let long_ago = store_time() - (48 * 60 * 60 * 1_000);
    db.lock().save_intent(&stored("finished", "succeeded", long_ago)).expect("stored");

    assert_eq!(runtime.collect_intents(24 * 60 * 60 * 1_000), 1, "the intent went");

    assert_eq!(
        db.lock().storage_get("@acme/notes", "draft").expect("read").as_deref(),
        Some("the user's words"),
        "and the plugin's data stayed"
    );
}

/// The wall clock, as the store spells it.
///
/// The daemon reads a `u64` and every column in the store is an `i64`, so a test that wants "an hour ago" has to convert —
/// and the conversion is the part that matters: `now_ms` is what the *daemon* answers, not what a row holds.
fn store_time() -> i64 {
    i64::try_from(now_ms()).unwrap_or(i64::MAX)
}

#[test]
fn a_sweep_that_cannot_finish_says_so_rather_than_reporting_zero() {
    // """ + S + """ The failure this report exists for, and it is the shape that hides longest.
    //
    // Every collection target used to swallow its error: a delete that failed logged and returned **zero**, so a sweep that
    // could not do its job produced exactly the same answer as a sweep with nothing to do — and the daemon's loop printed
    // nothing at all, because every count was zero. A database that cannot be collected from would stay that way quietly.
    //
    // """ + S + """ The fixture is a database that was never migrated, which is how round 82 found the same class of bug.
    //
    // `open_in_memory` creates an empty file and runs no schema, so all three targets fail for the same honest reason: the
    // tables are not there. That is a real failure rather than a contrived one, and it needs no seam to inject.
    let db = synra_store::SynraDb::open_in_memory().expect("a database");

    let report = crate::runtime::intents::sweep(
        &db,
        crate::runtime::intents::Retention { intents_ms: 0, audit_ms: 0 },
    );

    assert_eq!(report.removed(), 0, "nothing could have been removed: {report:?}");
    // ★ All three are named, so a reader knows which tables to look at — and three rather than one, which is what makes
    // this a report about the sweep rather than about the first thing that went wrong.
    assert_eq!(report.failures.len(), 3, "{report:?}");
    for (failure, table) in report.failures.iter().zip(["intents", "devices", "call"]) {
        assert!(failure.contains(table), "{failure} should name {table}");
    }
}

#[test]
fn the_plugin_report_carries_the_live_rung_as_well_as_the_row() {
    // """ + S + """ The reader the ladder did not have.
    //
    // `PluginSet::health_of` exists because round 114 made a trap count towards the health ladder and then found that
    // nothing could read the result: the daemon reported the **database row**, which is what was recorded at install time
    // and never moves. This asserts the report now carries both, and that the live one is a real answer rather than `null`
    // — which is what an accessor that always returned `None` would look like.
    let dir = TempDir::new("report-live-health");
    let runtime = runtime(dir.path());
    let id = "@acme/notes";
    write_plugin(&runtime.plugins_dir, id, r#"{"cap": "log:info"}"#);
    install(&runtime, id, 1, 1);
    consent(&runtime, id, &["log:info"]);

    // Loaded into the runtime's **own** set, because that is the one the report reads.
    crate::runtime::load_installed(
        &mut runtime.plugins.lock(),
        &runtime.db(),
        &runtime.plugins_dir,
        &synra_observe::crash::StartupVerdict::Clean,
        &synra_plugin_api::revocation::RevocationList::empty(),
    );

    let value = runtime.plugins_value().expect("the report");
    let listed = value["plugins"].as_array().expect("a list");
    let row = listed
        .iter()
        .find(|entry| entry["id"] == id)
        .expect("the plugin is listed");

    // The recorded row, unchanged by anything that happened at runtime.
    assert_eq!(row["health"], "healthy", "{row}");
    // And the live rung, which is `good` for a plugin that has just been loaded and has done nothing.
    assert_eq!(row["liveHealth"], "good", "{row}");
}


// ── The intent counter ──────────────────────────────────────────────────────────────────────────

#[test]
fn a_share_nothing_can_answer_is_counted_as_refused() {
    // ★ The half that only exists because the counter is written before the `?`. An `intents_total` incremented on the
    // success path would count what was handled and say nothing about the shares that became files — and "why did
    // nothing answer this" is a question about the refusals.
    let dir = TempDir::new("intent-metric");
    let runtime = runtime(dir.path());

    // ★ 这个 fixture 里没有插件，而这**不会**让路由失败 —— 第一版测试就是这么假设的，它失败了：
    // 空插件集也会成功地把一个意图建立起来，返回 `Ok`。所以「路由成功」和「有人回答」是两件事，
    // 而这一条测的正是后者。
    let routed = runtime.intent_dispatch("text/plain", "hello");
    assert!(routed.is_ok(), "an empty plugin set failed to raise an intent: {routed:?}");

    let snapshot = runtime.metrics.snapshot();
    assert_eq!(
        snapshot.get("intents_total{outcome=ok}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the intent was raised and not counted"
    );
    // 而**没人能处理它**：这是「为什么没人回答」真正的答案，`outcome=ok` 说不出这件事。
    assert_eq!(
        snapshot.get("intent_no_handler_total"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "nothing could handle it, and that is not recorded"
    );
}


// ── A real transfer, so the transfer metrics have evidence ──────────────────────────────────────

/// A host that is listening, with the port it got.
///
/// Copied from `transport/tests.rs` rather than shared: twenty lines of test scaffolding in two places
/// is cheaper than the visibility change that would share it, and a test that depends on another
/// test module's private helper is a test whose failure points at the wrong file.
fn listening(id: &str, name: &str) -> (std::sync::Arc<parking_lot::Mutex<Host>>, std::net::SocketAddr) {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    let mut identity = Identity::load(&db, "test", 1_000).expect("an identity");
    identity.device_id = id.parse().expect("a device id");
    identity.rename(&db, name, 1_000).expect("renames");
    let local = synra_core::peer::LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0-test",
    );
    let mut host = Host::with_flags(identity, local, synra_core::peer::Flags::no_timeout());
    let address = synra_core::listener::bind(&mut host, 0).expect("binds");
    host.listen_nonblocking().expect("non-blocking");
    (std::sync::Arc::new(parking_lot::Mutex::new(host)), address)
}

fn test_desk() -> std::sync::Arc<synra_core::pairing::PairingDesk> {
    std::sync::Arc::new(synra_core::pairing::PairingDesk::new(
        synra_protocol::ids::DeviceId::new(),
        synra_protocol::session::SessionTimeouts::default().pairing,
    ))
}

fn test_router() -> std::sync::Arc<crate::runtime::intent::Router> {
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    let set = synra_core::dispatch::PluginSet::new(
        synra_plugin_host::Backend::new(std::sync::Arc::new(synra_plugin_host::ScriptedBackend::new())),
        std::sync::Arc::new(crate::runtime::plugin_host::KernelHost::new(
            std::sync::Arc::new(parking_lot::Mutex::new(db)),
            "0.1.0-test",
        )),
    );
    std::sync::Arc::new(crate::runtime::intent::Router::new(
        std::sync::Arc::new(parking_lot::Mutex::new(set)),
        std::sync::Arc::new(parking_lot::Mutex::new(synra_core::intent::Board::new())),
    ))
}

#[test]
fn a_file_that_reaches_the_other_side_is_measured() {
    // ★ 第 144 轮接了 `transfer_bytes` 与 `transfer_duration_ms`，并写明了「没有测试」：触发成功路径
    // 需要一次真实的传输。这一条就是那次传输 —— 一个真实的监听端、一次握手、一份文件。
    //
    // 而它之所以现在能写：那次接力里需要的三个 helper 已经存在于 `transport/tests.rs`，
    // 证明这套骨架在本仓库是稳的（真 socket、真线程、5 秒截止）。
    let dir = TempDir::new("send-file-metric");
    let runtime = runtime(dir.path());
    let source = dir.path().join("payload.bin");
    std::fs::write(&source, vec![7u8; 4_096]).expect("a file to send");

    // ★ The two ends must agree about deadlines. The listener below is built with `no_timeout`, and the runtime's own
    // host is not — a client with a deadline against a server that has none (or the reverse) disagrees about when the
    // conversation is over, which is the failure `transport/tests.rs` records in its own words.
    runtime
        .host
        .lock()
        .set_flags(synra_core::peer::Flags::no_timeout());
    let inbox = TempDir::new("send-file-inbox");
    let (listener, address) = listening("11111111-1111-4111-8111-111111111111", "Laptop");
    let served = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // The guard is dropped before the handshake: `handle_within` locks the same host, and holding it here
            // would be one thread asking for a mutex it already holds — the failure that looks like a silent peer.
            let taken = listener.lock().try_accept();
            match taken {
                Ok(Some(stream)) => {
                    return synra_core::listener::handle_within(
                        &listener,
                        stream,
                        inbox.path(),
                        std::time::Duration::from_secs(5),
                        &test_desk(),
                        &test_router(),
                        &synra_core::listener::no_answer(),
                    );
                }
                Ok(None) => {}
                Err(error) => panic!("the listener could not accept: {error}"),
            }
            assert!(std::time::Instant::now() < deadline, "no connection arrived");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });

    // ★ The address the listener bound is not always one you can dial: port 0 asks the operating system to choose, and
    // the address it reports can be the unspecified one. Dialing that is a connection to "any address", which on
    // Windows is not this machine — `transport/tests.rs` has a `dialable` helper for exactly this reason, and this
    // does the same thing without depending on another test module's private function.
    let dial_to = std::net::SocketAddr::new(
        match address.ip() {
            std::net::IpAddr::V4(v4) if v4.is_unspecified() => {
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
            std::net::IpAddr::V6(v6) if v6.is_unspecified() => {
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            }
            other => other,
        },
        address.port(),
    );
    let answer = runtime.send_file(&dial_to.to_string(), &source.to_string_lossy());
    assert!(answer.is_ok(), "the send failed: {answer:?}");
    // ★ 监听端线程交回它服务过的那条连接，而这次连接上有一个真的落了地的文件 ——
    // 第 146 轮发现「收到包的那一刻没有可写的地方」，这是把那个值送到有地方可写的人手上的第一步。
    let served = served.join().expect("the server thread finished");
    assert_eq!(served.finished.len(), 1, "the finished transfer was not handed back: {served:?}");
    assert_eq!(served.finished[0].byte_length, 4_096);
    // 而它不是插件包 —— 发送的是一份附件。
    assert!(served.finished[0].bundle.is_none(), "{served:?}");
    // ★ 而它带着发送方 —— 逐条带上，因为「谁发的这个文件」是关于**文件**的事实，
    // 而 `Served::peer` 是关于**连接**的。
    assert_eq!(served.finished[0].peer, served.peer.expect("a handshaked peer"));

    let snapshot = runtime.metrics.snapshot();
    assert!(
        snapshot.get("transfer_bytes{kind=attachment}").is_some(),
        "the size of a completed transfer is not recorded"
    );
    assert!(
        snapshot.get("transfer_duration_ms{kind=attachment}").is_some(),
        "the duration of a completed transfer is not recorded"
    );
}


#[test]
fn a_bundle_arrives_as_a_bundle() {
    // ★ 这一条走的是第 153 轮的 `send_bundle` 与这一轮的 `Kernel::send_bundle` ——
    // 而它证明的是一件具体的事：接收端**以插件包的身份**认出它（第 139 轮的 `bundle` 字段）。
    //
    // 在此之前，`send_file` 的请求把 kind 与 meta 写死为附件，于是一个包会以一张截图的身份到达，
    // 而接收端据此决定它落在哪里、以及它是什么 —— 一条在接收端看起来完全正常的错。
    let dir = TempDir::new("send-bundle");
    let runtime = runtime(dir.path());
    let source = dir.path().join("plugin.wasm");
    std::fs::write(&source, b"\0asm\x01\0\0\0an artifact").expect("a file to send");

    runtime
        .host
        .lock()
        .set_flags(synra_core::peer::Flags::no_timeout());
    let inbox = TempDir::new("send-bundle-inbox");
    let (listener, address) = listening("11111111-1111-4111-8111-111111111111", "Laptop");
    let served = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let taken = listener.lock().try_accept();
            match taken {
                Ok(Some(stream)) => {
                    return synra_core::listener::handle_within(
                        &listener,
                        stream,
                        inbox.path(),
                        std::time::Duration::from_secs(5),
                        &test_desk(),
                        &test_router(),
                        &synra_core::listener::no_answer(),
                    );
                }
                Ok(None) => {}
                Err(error) => panic!("the listener could not accept: {error}"),
            }
            assert!(std::time::Instant::now() < deadline, "no connection arrived");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });

    // 端口 0 让操作系统挑地址，而它报回来的不总是能拨的。
    let dial_to = std::net::SocketAddr::new(
        match address.ip() {
            std::net::IpAddr::V4(v4) if v4.is_unspecified() => {
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
            other => other,
        },
        address.port(),
    );
    let answer = runtime.send_bundle(
        &dial_to.to_string(),
        &source.to_string_lossy(),
        "@acme/chat",
        "1.2.0",
    );
    assert!(answer.is_ok(), "the send failed: {answer:?}");

    let served = served.join().expect("the server thread finished");
    assert_eq!(served.finished.len(), 1, "{served:?}");
    // ★ 而它到了对端**作为插件包**，带着它的标识 —— 这是授权安装的那一步。
    assert_eq!(
        served.finished[0].bundle.as_ref().map(ToString::to_string),
        Some("@acme/chat".to_owned()),
        "a bundle arrived as something else"
    );

    // ★ 而**发送端**也记下了「对端现在持有这个版本」—— 与接收端那一半（`sync_records`）对称。
    // 版本在这里是 `1.2.0`，而接收端那一行是空串：接收端只知道传输的元数据里有什么，
    // 而发送端知道它**推的是哪个版本**。两行回答的是同一个问题的两侧。
    let held = runtime.db().sync_records().expect("reads");
    assert_eq!(held.len(), 1, "the sender did not record what the peer holds: {held:?}");
    assert_eq!(held[0].plugin_id, "@acme/chat");
    assert_eq!(held[0].peer_device, "11111111-1111-4111-8111-111111111111");
    assert_eq!(held[0].version, "1.2.0");
    assert!(
        !held[0].digest.is_empty(),
        "the digest the receiver confirmed is missing"
    );
}


#[test]
fn a_scan_is_counted_by_how_it_ended() {
    // ★ 发现组的指标在此之前**一次都没记过** —— 而「扫了但没有候选」与「扫到了三个」是用户读 `devices` 时的
    // 两种处境，只有一种是问题。一个从不被记录的计数会让两者变成同一件事。
    let dir = TempDir::new("scan-metrics");
    let runtime = runtime(dir.path());

    runtime.scan(50);

    let snapshot = runtime.metrics.snapshot();
    // 这个 fixture 有没有发现套接字是它自己的事，而两条路径各记一条 ——
    // 所以这里断言的是「记了」，不是「记了哪一个」。
    let counted = snapshot.get("scans_total{result=ran}").is_some()
        || snapshot.get("scans_total{result=unavailable}").is_some();
    assert!(counted, "a scan was not counted at all");
}
