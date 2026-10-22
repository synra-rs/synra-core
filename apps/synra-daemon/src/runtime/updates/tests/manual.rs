use super::*;
use synra_control::{Client, Listener, Request, Response};
use synra_protocol::error::ErrorCode;

fn answer(client: &mut Client, request: &Request) -> serde_json::Value {
    match client.ask(request).expect("control response") {
        Response::Ok { value } => value,
        other => panic!("request {request:?}: {other:?}"),
    }
}

#[test]
fn a_source_changed_during_download_is_refused_before_the_old_instance_stops() {
    let root = crate::runtime::tests::TempDir::new("manual-source-race");
    let runtime = Arc::new(installed(root.path()));
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "never", false);
    let held = registry.tarball.lock();
    let (done, finished) = std::sync::mpsc::channel();
    let kernel = Arc::clone(&runtime);
    let worker = std::thread::spawn(move || {
        done.send(kernel.plugin_update("@acme/hello", None))
            .expect("result");
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while registry.requests.load(Ordering::SeqCst) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "download did not start"
        );
        std::thread::yield_now();
    }
    assert!(
        runtime.db.try_lock().is_some(),
        "download must release the store"
    );
    assert!(
        runtime.plugins.try_lock().is_some(),
        "download must release the engine"
    );
    runtime
        .plugin_registry(Some(&["https://replacement.example".to_owned()]))
        .expect("change source");
    drop(held);
    let refused = finished
        .recv_timeout(Duration::from_secs(5))
        .expect("bounded result")
        .expect_err("source changed");
    worker.join().expect("update joined");
    assert!(refused.message.contains("registry changed"));
    assert_eq!(
        runtime
            .plugins
            .lock()
            .version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
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
}

#[test]
fn explicit_updates_cannot_bypass_safe_mode_or_candidate_revocation() {
    for safe_mode in [true, false] {
        let root = crate::runtime::tests::TempDir::new(&format!("manual-revoked-{safe_mode}"));
        let mut runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0", 7, false);
        registry.publish(&next, "1.1.0", false);
        configure(&runtime, &registry, "never", false);
        if safe_mode {
            runtime.plugin_loads.lock().safe_mode = Some("safe mode".to_owned());
        } else {
            runtime.revocations = synra_plugin_api::revocation::RevocationList::parse(r#"{"revoked":[{"plugin":"@acme/hello","versions":["1.1.0"],"reason":"withdrawn"}]}"#).expect("revocation");
        }
        assert!(runtime.plugin_update("@acme/hello", None).is_err());
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            usize::from(!safe_mode)
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

fn publisher_decisions_gate_updates(runtime: &Runtime, client: &mut Client) {
    let publishers = answer(client, &Request::PluginPublishers);
    let row = &publishers["publishers"][0];
    assert_eq!(row["publisherId"], "@acme");
    assert_eq!(row["trust"], "trusted");
    assert!(row.get("pubkey").is_none());
    let fingerprint = row["fingerprint"].as_str().expect("fingerprint");
    for (publisher_id, key, trust) in [
        ("@ghost", fingerprint, "trusted"),
        ("@acme", "1111 2222 3333 4444", "trusted"),
        ("@acme", fingerprint, "maybe"),
    ] {
        let response = client
            .ask(&Request::PluginPublisherDecide {
                publisher_id: publisher_id.to_owned(),
                fingerprint: key.to_owned(),
                trust: trust.to_owned(),
            })
            .expect("refusal response");
        assert!(matches!(response, Response::Failed { code, .. } if code == ErrorCode::InvalidArgument.as_str()));
    }
    for trust in ["seen", "revoked"] {
        let decision = answer(
            client,
            &Request::PluginPublisherDecide {
                publisher_id: "@acme".to_owned(),
                fingerprint: fingerprint.to_owned(),
                trust: trust.to_owned(),
            },
        );
        assert_eq!(decision["publisher"]["trust"], trust);
        assert!(decision["publisher"]["decidedMs"].is_i64());
    }
    assert!(!client.ask(&Request::PluginUpdate {
        plugin_id: "@acme/hello".to_owned(),
        version: None,
    }).expect("revoked key refusal").is_ok());
    assert_eq!(
        runtime.db().active_plugin("@acme/hello").expect("row").expect("installed").version,
        "1.0.0"
    );
    assert_eq!(
        runtime.plugins.lock().version(&PluginId::parse("@acme/hello").expect("id")),
        None,
        "a revoked key stops the running instance, not only the next download"
    );
    let confirmed = answer(
        client,
        &Request::PluginPublisherDecide {
            publisher_id: "@acme".to_owned(),
            fingerprint: fingerprint.to_lowercase(),
            trust: "trusted".to_owned(),
        },
    );
    assert_eq!(confirmed["publisher"]["fingerprint"], fingerprint);
    // The revocation switched the plugin off and untrusted it; trusting the key again is not the same decision as
    // approving the plugin, so the caller's next step needs both.
    runtime
        .plugin_consent("@acme/hello", &["log:*".to_owned()])
        .expect("consent after re-trust");
    runtime
        .plugin_set_enabled("@acme/hello", true)
        .expect("re-enable after re-trust");
    assert_eq!(
        runtime.plugins.lock().version(&PluginId::parse("@acme/hello").expect("id")),
        Some("1.0.0")
    );
}

#[test]
fn real_control_requests_configure_check_and_update_both_registry_formats() {
    for is_static in [false, true] {
        let root = crate::runtime::tests::TempDir::new(&format!("manual-wire-{is_static}"));
        let runtime = Arc::new(installed(root.path()));
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0", 7, false);
        registry.publish(&next, "1.1.0", is_static);
        let listener = Listener::bind(root.path()).expect("control socket");
        let kernel = Arc::clone(&runtime);
        let (completed, completion) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            completed
                .send(listener.serve_one(kernel.as_ref()))
                .expect("completion");
        });
        let mut client = Client::connect(root.path()).expect("client");
        client.handshake().expect("handshake");
        assert!(answer(&mut client, &Request::PluginRegistry { urls: None })["registry"].is_null());
        assert_eq!(
            answer(&mut client, &Request::PluginUpdatePolicy { policy: None })["updatePolicy"],
            "notify-only"
        );
        let url = if is_static {
            format!("static:{}", registry.base)
        } else {
            registry.base.clone()
        };
        answer(
            &mut client,
            &Request::PluginRegistry {
                urls: Some(vec![url.clone()]),
            },
        );
        assert_eq!(
            answer(&mut client, &Request::PluginRegistry { urls: None })["registry"],
            serde_json::json!([url])
        );
        answer(
            &mut client,
            &Request::PluginUpdatePolicy {
                policy: Some("auto-all".to_owned()),
            },
        );
        let checks = answer(
            &mut client,
            &Request::PluginCheckUpdates { plugin_id: None },
        );
        assert_eq!(checks["updateChecks"][0]["availableVersion"], "1.1.0");
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            1,
            "an explicit check must not download a package"
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
        answer(
            &mut client,
            &Request::PluginUpdatePolicy {
                policy: Some("never".to_owned()),
            },
        );
        let repeated = answer(
            &mut client,
            &Request::PluginCheckUpdates {
                plugin_id: Some("@acme/hello".to_owned()),
            },
        );
        assert_eq!(repeated["updateChecks"][0]["availableVersion"], "1.1.0");
        assert_eq!(
            registry.requests.load(Ordering::SeqCst),
            2,
            "manual checks ignore both never and the daily cache"
        );
        publisher_decisions_gate_updates(&runtime, &mut client);
        let updated = answer(
            &mut client,
            &Request::PluginUpdate {
                plugin_id: "@acme/hello".to_owned(),
                version: Some("^1.1".to_owned()),
            },
        );
        assert_eq!(updated["version"], "1.1.0");
        assert_eq!(updated["loaded"], true);
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some("1.1.0")
        );
        assert!(
            !client
                .ask(&Request::PluginUpdate {
                    plugin_id: "@acme/hello".to_owned(),
                    version: None
                })
                .expect("same version refused")
                .is_ok()
        );
        assert_eq!(
            runtime
                .plugins
                .lock()
                .version(&PluginId::parse("@acme/hello").expect("id")),
            Some("1.1.0")
        );
        answer(
            &mut client,
            &Request::PluginRegistry {
                urls: Some(Vec::new()),
            },
        );
        assert_eq!(
            client
                .ask(&Request::PluginCheckUpdates { plugin_id: None })
                .expect("no registry")
                .error_code(),
            Some(ErrorCode::Unsupported.as_str())
        );
        drop(client);
        completion
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded server shutdown")
            .expect("connection served");
        worker.join().expect("server joined");
    }
}

#[test]
fn invalid_settings_and_missing_targets_have_no_installation_side_effects() {
    let root = crate::runtime::tests::TempDir::new("manual-invalid");
    let runtime = installed(root.path());
    for url in [
        "http://example.com",
        "ftp://example.com",
        "https://user@example.com",
        "https://example.com/path",
        "static:https://example.com?token=secret",
    ] {
        assert!(
            runtime.plugin_registry(Some(&[url.to_owned()])).is_err(),
            "{url}"
        );
    }
    assert!(runtime.plugin_update_policy(Some("yes")).is_err());
    assert!(runtime.db().config().expect("config").is_empty());
    let registry = Registry::start();
    configure(&runtime, &registry, "never", false);
    assert_eq!(
        runtime
            .plugin_check_updates(Some("@acme/missing"))
            .expect_err("missing")
            .code,
        ErrorCode::PluginNotInstalled
    );
    assert_eq!(
        runtime
            .plugin_update("@acme/missing", None)
            .expect_err("missing")
            .code,
        ErrorCode::PluginNotInstalled
    );
    assert_eq!(registry.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn checks_preserve_cached_answers_and_report_per_plugin_network_failures() {
    let root = crate::runtime::tests::TempDir::new("manual-offline");
    let runtime = installed(root.path());
    let registry = Registry::start();
    let next = root.path().join("next");
    signed_source(&next, "1.1.0", 7, false);
    registry.publish(&next, "1.1.0", false);
    configure(&runtime, &registry, "never", false);
    let first = super::super::manual::check(&runtime, None, 100).expect("check");
    *registry.document.lock() = (503, "offline".to_owned());
    let offline = super::super::manual::check(&runtime, None, 200).expect("report");
    assert_eq!(first["updateChecks"], offline["updateChecks"]);
    assert_eq!(offline["failures"].as_array().expect("failures").len(), 1);
}

#[test]
fn manual_updates_reset_consent_for_new_permissions_and_refuse_key_changes_or_tampering() {
    for (label, seed, extra, tamper) in [
        ("caps", 7, true, false),
        ("faulted", 7, true, false),
        ("key", 9, false, false),
        ("tamper", 7, false, true),
    ] {
        let root = crate::runtime::tests::TempDir::new(&format!("manual-{label}"));
        let runtime = installed(root.path());
        let registry = Registry::start();
        let next = root.path().join("next");
        signed_source(&next, "1.1.0-beta.1", seed, extra);
        registry.publish(&next, "1.1.0-beta.1", false);
        configure(&runtime, &registry, "never", false);
        if label == "faulted" {
            let id = PluginId::parse("@acme/hello").expect("id");
            synra_core::plugin::deactivate(&mut runtime.plugins.lock(), &id, 1);
            runtime
                .plugin_loads
                .lock()
                .record_refused("@acme/hello", "old activation failed".to_owned());
        }
        if tamper {
            registry.tarball.lock().1.push(0);
            assert_eq!(
                runtime
                    .plugin_update("@acme/hello", None)
                    .expect_err("integrity")
                    .code,
                ErrorCode::IntegrityMismatch
            );
            assert_eq!(
                runtime
                    .plugins
                    .lock()
                    .version(&PluginId::parse("@acme/hello").expect("id")),
                Some("1.0.0")
            );
        } else if seed != 7 {
            let refused = runtime
                .plugin_update("@acme/hello", Some("1.1.0-beta.1"))
                .expect_err("changed signer");
            assert!(refused.message.contains("publisher-trust"));
            assert_eq!(
                runtime
                    .plugins
                    .lock()
                    .version(&PluginId::parse("@acme/hello").expect("id")),
                Some("1.0.0")
            );
        } else {
            let updated = runtime
                .plugin_update("@acme/hello", Some("1.1.0-beta.1"))
                .expect("manual prerelease");
            assert_eq!(updated["loaded"], false);
            assert_eq!(updated["enabled"], false);
            assert!(
                updated["activationError"].is_null(),
                "old activation failures must not describe the new version"
            );
            let row = runtime.db().plugins().expect("plugins").remove(0);
            assert!(!row.enabled && !row.trusted);
            assert!(
                !runtime
                    .plugins
                    .lock()
                    .contains(&PluginId::parse("@acme/hello").expect("id"))
            );
        }
        let staging = runtime.paths.cache_dir().join("registry");
        assert!(
            !staging.exists()
                || std::fs::read_dir(staging)
                    .expect("staging")
                    .next()
                    .is_none()
        );
    }
}
