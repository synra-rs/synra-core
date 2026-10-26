use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use synra_control::Kernel as _;
use synra_core::plugin_updates::{AUTO_UPDATE_KEY, CHECK_EVERY_MS};
use synra_protocol::PluginId;

use super::*;

struct Registry {
    base: String,
    document: Arc<Mutex<(u16, String)>>,
    tarball: Arc<Mutex<(u16, Vec<u8>)>>,
    requests: Arc<AtomicUsize>,
    cancel: Cancellation,
    worker: Option<std::thread::JoinHandle<()>>,
}

mod manual;

impl Registry {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let document = Arc::new(Mutex::new((200, String::new())));
        let tarball = Arc::new(Mutex::new((200, Vec::new())));
        let requests = Arc::new(AtomicUsize::new(0));
        let cancel = Cancellation::new();
        let (text, bytes, counted, stop) = (
            Arc::clone(&document),
            Arc::clone(&tarball),
            Arc::clone(&requests),
            cancel.clone(),
        );
        let worker = std::thread::spawn(move || {
            while !stop.is_cancelled() {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("blocking accepted socket");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read deadline");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write deadline");
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                            let mut byte = [0];
                            if stream.read_exact(&mut byte).is_err() {
                                break;
                            }
                            request.extend(byte);
                        }
                        counted.fetch_add(1, Ordering::SeqCst);
                        let (status, body) = if String::from_utf8_lossy(&request).contains(".tgz ")
                        {
                            bytes.lock().clone()
                        } else {
                            let (status, body) = text.lock().clone();
                            (status, body.into_bytes())
                        };
                        write!(stream, "HTTP/1.1 {status} Result\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()).expect("headers");
                        stream.write_all(&body).expect("body");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stop.wait(Duration::from_millis(2)) {
                            break;
                        }
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            }
        });
        Self {
            base,
            document,
            tarball,
            requests,
            cancel,
            worker: Some(worker),
        }
    }

    fn publish(&self, directory: &Path, version: &str, is_static: bool) {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for file in ["manifest.json", "plugin.wasm", "signature.json"] {
            tar.append_path_with_name(directory.join(file), format!("package/{file}"))
                .expect("tar entry");
        }
        let bytes = tar.into_inner().expect("tar").finish().expect("gzip");
        let integrity = synra_core::transfer::ObjectDigest::of(&bytes)
            .as_sri()
            .to_string();
        let document = if is_static {
            serde_json::json!({"name":"@acme/hello", "latest":version,
                "versions":[{"version":version, "tarball":"hello.tgz", "integrity":integrity}]})
        } else {
            serde_json::json!({"name":"@acme/hello", "dist-tags":{"latest":version},
                "versions":{version:{"name":"@acme/hello", "version":version,
                    "dist":{"tarball":format!("{}/hello.tgz", self.base), "integrity":integrity}}}})
        };
        *self.document.lock() = (200, document.to_string());
        *self.tarball.lock() = (200, bytes);
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = self.worker.take() {
            worker.join().expect("server stopped");
        }
    }
}

fn signed_source(directory: &Path, version: &str, seed: u8, extra: bool) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use synra_plugin_api::publisher::{Digests, SigningSubject};

    std::fs::create_dir_all(directory).expect("source");
    let capabilities = if extra {
        serde_json::json!([{"cap":"log:*"}, {"cap":"device:send:*"}])
    } else {
        serde_json::json!([{"cap":"log:*"}])
    };
    let manifest = serde_json::json!({"id":"@acme/hello", "version":version, "title":"Hello", "publisher":{"id":"@acme"},
        "sdk":{"min":"0.1.0"}, "wit":synra_plugin_host::host_world(), "capabilities":capabilities,
        "runtime":{"headless":{"artifact":"plugin.wasm", "stateful":false}}}).to_string();
    let wasm = b"\0asm\x01\0\0\0";
    let mut artifacts = Digests::new();
    artifacts.insert(
        "plugin.wasm",
        synra_core::transfer::ObjectDigest::of(wasm)
            .as_sri()
            .to_string(),
    );
    let subject = SigningSubject {
        manifest: synra_plugin_api::manifest_digest(&manifest),
        artifacts,
    };
    let key = SigningKey::from_bytes(&[seed; 32]);
    let signature = serde_json::json!({"version":1, "publisher":{"id":"@acme"}, "algorithm":"ed25519", "signedAt":"2026-10-22T00:00:00Z",
        "pubkey":STANDARD.encode(key.verifying_key().as_bytes()),
        "subject":{"manifest":subject.manifest, "artifacts":subject.artifacts.iter().collect::<std::collections::BTreeMap<_,_>>()},
        "signature":STANDARD.encode(key.sign(&subject.canonical_bytes()).to_bytes())});
    std::fs::write(directory.join("manifest.json"), manifest).expect("manifest");
    std::fs::write(directory.join("signature.json"), signature.to_string()).expect("signature");
    std::fs::write(directory.join("plugin.wasm"), wasm).expect("wasm");
}

fn installed(root: &Path) -> Runtime {
    let runtime = super::super::tests::runtime(root);
    let first = root.join("first");
    signed_source(&first, "1.0.0", 7, false);
    runtime
        .plugin_install(first.to_str().expect("path"))
        .expect("install");
    let fingerprint = runtime.db().publishers().expect("publishers")[0]
        .fingerprint
        .clone();
    runtime
        .db()
        .set_publisher_trust("@acme", &fingerprint, synra_store::TRUST_TRUSTED, 1)
        .expect("trust publisher");
    runtime
        .plugin_consent("@acme/hello", &["log:*".to_owned()])
        .expect("consent");
    runtime
        .plugin_set_enabled("@acme/hello", true)
        .expect("enable");
    runtime
}

fn configure(runtime: &Runtime, registry: &Registry, policy: &str, is_static: bool) {
    let url = if is_static {
        format!("static:{}", registry.base)
    } else {
        registry.base.clone()
    };
    runtime
        .db()
        .set_config(source::REGISTRY_KEY, &serde_json::json!(url), 1)
        .expect("registry");
    runtime
        .db()
        .set_config(AUTO_UPDATE_KEY, &serde_json::json!(policy), 1)
        .expect("policy");
}

#[test]
fn both_registry_formats_apply_only_policy_and_signature_admitted_updates() {
    for (index, (version, policy, seed, extra, is_static, applies)) in [
        ("1.0.1", "auto-minor", 7, false, false, true),
        ("1.1.0", "auto-minor", 7, false, true, true),
        ("2.0.0", "auto-all", 7, false, false, true),
        ("2.0.0", "auto-minor", 7, false, false, false),
        ("1.1.0", "auto-all", 9, false, false, false),
        ("1.1.0", "auto-all", 7, true, false, false),
        ("1.1.0", "notify-only", 7, false, false, false),
        ("1.1.0", "never", 7, false, false, false),
    ]
    .into_iter()
    .enumerate()
    {
        let root = super::super::tests::TempDir::new(&format!("update-matrix-{index}"));
        let runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, version, seed, extra);
        registry.publish(&next, version, is_static);
        configure(&runtime, &registry, policy, is_static);
        let updates = check_all(&runtime, 100, &Cancellation::new());
        let expected = if applies { version } else { "1.0.0" };
        assert_eq!(
            runtime
                .db()
                .active_plugin("@acme/hello")
                .expect("row")
                .expect("installed")
                .version,
            expected,
            "case {index}"
        );
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some(expected),
            "running case {index}"
        );
        assert_eq!(updates.is_empty(), applies || policy == "never");
        if !applies && policy != "never" {
            let listing = runtime.plugins().expect("report");
            assert_eq!(listing["plugins"][0]["update"]["version"], version);
            assert_eq!(listing["plugins"][0]["updateCheckedAtMs"], 100);
        }
        if policy == "notify-only" {
            assert_eq!(registry.requests.load(Ordering::SeqCst), 1);
        }
        if policy == "never" {
            assert_eq!(registry.requests.load(Ordering::SeqCst), 0);
        }
        let cache = runtime.paths.cache_dir().join("registry");
        assert!(
            !cache.exists() || cache.read_dir().expect("cache").next().is_none(),
            "download cleanup"
        );
    }
}

#[test]
fn failed_downloads_back_off_across_restart_and_preserve_the_installed_version() {
    let root = super::super::tests::TempDir::new("bounded-update-retries");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    *registry.tarball.lock() = (503, b"unavailable".to_vec());
    configure(&runtime, &registry, "auto-all", false);
    let cancel = Cancellation::new();
    assert_eq!(check_all(&runtime, 100, &cancel).len(), 1);
    let saved = runtime
        .db()
        .plugin_update_check("@acme/hello")
        .expect("read")
        .expect("check");
    assert_eq!(saved.attempts, 1);
    let backup = root.path().join("retry-restart.sqlite3");
    runtime.db().backup_to(&backup).expect("snapshot");
    let mut restarted = super::super::tests::runtime(root.path());
    restarted.db = Arc::new(Mutex::new(
        synra_store::SynraDb::open(&backup).expect("reopen"),
    ));
    let mut next_attempt = saved.retry_at_ms.expect("deadline");
    for attempt in 2..=3 {
        let requests = registry.requests.load(Ordering::SeqCst);
        assert!(check_all(&restarted, next_attempt - 1, &cancel).is_empty());
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            requests,
            "no request before the retry deadline"
        );
        assert_eq!(check_all(&restarted, next_attempt, &cancel).len(), 1);
        assert!(registry.requests.load(Ordering::SeqCst) > requests);
        let saved = restarted
            .db()
            .plugin_update_check("@acme/hello")
            .expect("read")
            .expect("check");
        assert_eq!(saved.attempts, attempt);
        next_attempt = saved
            .retry_at_ms
            .unwrap_or(saved.checked_at_ms + CHECK_EVERY_MS);
        assert_eq!(saved.retry_at_ms.is_none(), attempt == 3);
    }
    let requests = registry.requests.load(Ordering::SeqCst);
    assert!(check_all(&restarted, next_attempt - 1, &cancel).is_empty());
    assert_eq!(
        registry.requests.load(Ordering::SeqCst),
        requests,
        "the daily check takes over"
    );
    assert_eq!(
        restarted
            .db()
            .active_plugin("@acme/hello")
            .expect("read")
            .expect("installed")
            .version,
        "1.0.0"
    );
}

#[test]
fn successful_checks_survive_restart_and_offline_failures_keep_the_last_answer() {
    let root = super::super::tests::TempDir::new("update-restart");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "notify-only", false);
    assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
    let backup = root.path().join("restart.sqlite3");
    runtime.db().backup_to(&backup).expect("snapshot");
    let mut restarted = super::super::tests::runtime(root.path());
    restarted.db = Arc::new(Mutex::new(
        synra_store::SynraDb::open(&backup).expect("reopen"),
    ));
    assert!(check_all(&restarted, 100 + CHECK_EVERY_MS - 1, &Cancellation::new()).is_empty());
    assert_eq!(registry.requests.load(Ordering::SeqCst), 1);
    *registry.document.lock() = (503, "offline".to_owned());
    assert!(check_all(&restarted, 100 + CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        restarted
            .db()
            .plugin_update_check("@acme/hello")
            .expect("saved")
            .expect("check")
            .available_version
            .as_deref(),
        Some("1.1.0")
    );
    registry.publish(&next, "1.0.0", false);
    assert!(check_all(&restarted, 100 + CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert!(
        restarted
            .db()
            .plugin_update_check("@acme/hello")
            .expect("negative")
            .expect("check")
            .available_version
            .is_none()
    );
}

#[test]
fn a_registered_worker_runs_and_shutdown_interrupts_its_five_minute_wait() {
    let root = super::super::tests::TempDir::new("update-worker");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "notify-only", false);
    let runtime = Arc::new(runtime);
    let supervisor = Arc::new(Supervisor::new(1));
    let worker = start(&runtime, &supervisor).expect("registered worker");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while runtime
        .db()
        .plugin_update_check("@acme/hello")
        .expect("saved")
        .is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "worker checked before deadline"
        );
        std::thread::yield_now();
    }
    let stopped = std::time::Instant::now();
    let _ = supervisor.begin_shutdown();
    while !worker.is_finished() {
        assert!(stopped.elapsed() < Duration::from_secs(5));
        std::thread::yield_now();
    }
    worker.join().expect("worker stopped");
    assert_eq!(registry.requests.load(Ordering::SeqCst), 1);
}

#[test]
fn real_downloads_keep_binary_bytes_and_refuse_http_errors() {
    use super::super::registry_install::{Fetch as _, NetworkFetch};
    let registry = Registry::start();
    let bytes: Vec<u8> = (0..=255).collect();
    *registry.tarball.lock() = (200, bytes.clone());
    assert!(
        NetworkFetch::default()
            .get(&format!("{}/hello.tgz", registry.base))
            .is_err(),
        "unconfigured loopback is refused"
    );
    assert_eq!(registry.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        NetworkFetch {
            allow_loopback: true
        }
        .get(&format!("{}/hello.tgz", registry.base))
        .expect("binary"),
        bytes
    );
    *registry.tarball.lock() = (403, b"forbidden".to_vec());
    assert!(
        NetworkFetch {
            allow_loopback: true
        }
        .get(&format!("{}/hello.tgz", registry.base))
        .expect_err("HTTP error")
        .contains("403")
    );
}

#[test]
fn mirrors_retry_network_failures_but_not_integrity_or_authorization_failures() {
    let root = super::super::tests::TempDir::new("update-mirrors");
    let runtime = installed(root.path());
    let first = Registry::start();
    let second = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    first.publish(&next, "1.1.0", false);
    second.publish(&next, "1.1.0", false);
    runtime
        .db()
        .set_config(
            source::REGISTRY_KEY,
            &serde_json::json!([first.base, second.base]),
            1,
        )
        .expect("mirrors");
    runtime
        .db()
        .set_config(AUTO_UPDATE_KEY, &serde_json::json!("auto-all"), 1)
        .expect("policy");
    first.tarball.lock().1.push(0);
    assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        0,
        "bad integrity never falls back"
    );
    *first.tarball.lock() = (403, Vec::new());
    assert_eq!(
        check_all(&runtime, 100 + CHECK_EVERY_MS, &Cancellation::new()).len(),
        1
    );
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        0,
        "authorization never falls back"
    );
    *first.document.lock() = (503, "offline".to_owned());
    assert!(check_all(&runtime, 100 + 2 * CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        2,
        "a working mirror supplies metadata and bytes"
    );
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.1.0")
    );
    *first.document.lock() = (200, "malformed metadata".to_owned());
    assert!(check_all(&runtime, 100 + 3 * CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        second.requests.load(Ordering::SeqCst),
        3,
        "a malformed mirror falls back to a fresh negative check"
    );
}

#[test]
fn safe_mode_and_known_revocations_preserve_the_installed_running_version() {
    for safe_mode in [true, false] {
        let root = super::super::tests::TempDir::new(&format!("update-revoked-{safe_mode}"));
        let mut runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0", 7, false);
        registry.publish(&next, "1.1.0", false);
        configure(&runtime, &registry, "auto-all", false);
        if safe_mode {
            runtime.plugin_loads.lock().safe_mode = Some("safe mode".to_owned());
        } else {
            runtime.revocations = synra_plugin_api::revocation::RevocationList::parse(r#"{"revoked":[{"plugin":"@acme/hello","versions":["1.1.0"],"reason":"withdrawn"}]}"#).expect("revocation");
        }
        assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            1,
            "no download for a forbidden replacement"
        );
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some("1.0.0")
        );
    }
}

#[test]
fn a_refused_commit_restores_the_old_files_permissions_and_running_instance() {
    let root = super::super::tests::TempDir::new("update-rollback");
    let mut runtime = installed(root.path());
    let registry = Registry::start();
    configure(&runtime, &registry, "auto-all", false);
    let previous = runtime.db().plugin_grants("@acme/hello").expect("grants");
    let raw = registry_setting(&runtime.db()).expect("registry");
    let backup = root.path().join("read-only.sqlite3");
    runtime.db().backup_to(&backup).expect("backup");
    runtime.db = Arc::new(Mutex::new(
        synra_store::SynraDb::open_read_only(&backup).expect("read-only database"),
    ));
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    assert!(
        apply::directory(
            &runtime,
            ("@acme/hello", "1.1.0"),
            &next,
            raw.as_deref(),
            UpdatePolicy::AutoAll,
            100,
            &Cancellation::new()
        )
        .is_err()
    );
    assert_eq!(
        runtime
            .db()
            .active_plugin("@acme/hello")
            .expect("row")
            .expect("installed")
            .version,
        "1.0.0"
    );
    assert_eq!(
        runtime.db().plugin_grants("@acme/hello").expect("grants"),
        previous
    );
    let manifest = std::fs::read_to_string(runtime.plugins_dir.join("acme+hello/manifest.json"))
        .expect("restored manifest");
    assert_eq!(
        synra_plugin_api::Manifest::from_json(&manifest)
            .expect("manifest")
            .version,
        "1.0.0"
    );
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
    );
    assert_eq!(runtime.plugin_loads.lock().len(), 1);
}

#[test]
fn cancellation_and_changed_policy_registry_or_target_do_not_stop_the_old_instance() {
    let root = super::super::tests::TempDir::new("update-cancel");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    for (policy, cancelled, changed_registry, plugin, version) in [
        ("never", false, false, "@acme/hello", "1.1.0"),
        ("auto-all", true, false, "@acme/hello", "1.1.0"),
        ("auto-all", false, true, "@acme/hello", "1.1.0"),
        ("auto-all", false, false, "@acme/other", "1.1.0"),
        ("auto-all", false, false, "@acme/hello", "2.0.0"),
    ] {
        configure(&runtime, &registry, policy, false);
        let raw = registry_setting(&runtime.db()).expect("registry");
        if changed_registry {
            runtime
                .db()
                .set_config(
                    source::REGISTRY_KEY,
                    &serde_json::json!("https://changed.example"),
                    1,
                )
                .expect("changed registry");
        }
        let cancel = Cancellation::new();
        if cancelled {
            cancel.cancel();
        }
        assert!(
            apply::directory(
                &runtime,
                (plugin, version),
                &next,
                raw.as_deref(),
                UpdatePolicy::AutoAll,
                100,
                &cancel
            )
            .is_err()
        );
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some("1.0.0")
        );
    }
}

#[test]
fn a_waiting_registry_does_not_hold_the_database_or_plugin_lock() {
    let root = super::super::tests::TempDir::new("update-locks");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "notify-only", false);
    let runtime = Arc::new(runtime);
    let held = registry.document.lock();
    let (done, finished) = std::sync::mpsc::channel();
    let worker = {
        let runtime = Arc::clone(&runtime);
        std::thread::spawn(move || {
            done.send(check_all(&runtime, 100, &Cancellation::new()))
                .expect("result")
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while registry.requests.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(
        runtime.db.try_lock().is_some(),
        "network requests release the store"
    );
    assert!(
        runtime.plugins.try_lock().is_some(),
        "network requests release the engine"
    );
    drop(held);
    assert_eq!(
        finished
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded result")
            .len(),
        1
    );
    worker.join().expect("worker");
}

#[test]
fn migration_failures_keep_the_old_version_and_activation_failures_report_the_committed_one() {
    use synra_plugin_host::{Backend, Scripted, ScriptedBackend, Work};
    let root = super::super::tests::TempDir::new("update-lifecycle");
    let mut runtime = installed(root.path());
    let engine = ScriptedBackend::new();
    let host = Arc::clone(runtime.plugins.lock().host());
    runtime.plugins = Arc::new(Mutex::new(synra_core::dispatch::PluginSet::new(
        Backend::new(Arc::new(engine.clone())),
        host,
    )));
    runtime
        .plugin_set_enabled("@acme/hello", true)
        .expect("old instance");
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "auto-all", false);
    let migrate = Work::Migrate {
        from_version: "1.0.0".to_owned(),
        to_version: "1.1.0".to_owned(),
    };
    engine.script_for(
        "@acme/hello",
        &migrate,
        Scripted::Failed {
            code: "migration".to_owned(),
            message: "cannot migrate".to_owned(),
            details: None,
        },
    );
    assert_eq!(check_all(&runtime, 100, &Cancellation::new()).len(), 1);
    assert_eq!(
        runtime
            .db()
            .active_plugin("@acme/hello")
            .expect("row")
            .expect("installed")
            .version,
        "1.0.0"
    );
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
    );
    engine.script_for("@acme/hello", &migrate, Scripted::Ok("null".to_owned()));
    let config_json = synra_core::plugin::activation_config(runtime.plugins.lock().host().as_ref());
    engine.script_for(
        "@acme/hello",
        &Work::Activate { config_json },
        Scripted::Failed {
            code: "activation".to_owned(),
            message: "cannot activate".to_owned(),
            details: None,
        },
    );
    assert!(check_all(&runtime, 100 + CHECK_EVERY_MS, &Cancellation::new()).is_empty());
    assert_eq!(
        runtime
            .db()
            .active_plugin("@acme/hello")
            .expect("row")
            .expect("installed")
            .version,
        "1.1.0"
    );
    assert!(
        runtime
            .plugin_loads
            .lock()
            .refusal_for("@acme/hello")
            .expect("activation refusal")
            .contains("cannot activate")
    );
}

#[test]
fn revoking_a_publisher_stops_its_installed_plugin() {
    // ★ The revocation is about the running code, not only the row the installer consults. v1 keeps one key per
    // publisher, so the installed manifest's publisher id names the same set the signature would.
    let root = super::super::tests::TempDir::new("publisher-revoke");
    let runtime = installed(root.path());
    let fingerprint = runtime.db().publishers().expect("publishers")[0]
        .fingerprint
        .clone();
    let id = PluginId::parse("@acme/hello").expect("a plugin id");
    assert!(
        runtime.plugins.lock().contains(&id),
        "the fixture starts loaded"
    );

    runtime
        .plugin_publisher_decide("@acme", &fingerprint, "revoked")
        .expect("revoke the key");

    let row = runtime
        .db()
        .plugins()
        .expect("plugins")
        .into_iter()
        .find(|row| row.plugin_id == "@acme/hello")
        .expect("the plugin row");
    assert!(!row.enabled, "a revoked publisher's plugin is switched off");
    assert!(!row.trusted, "and its trust goes with the key");
    assert!(
        !runtime.plugins.lock().contains(&id),
        "the running instance is unloaded"
    );
}
