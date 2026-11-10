use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use synra_control::{Client, Listener, Request, Response};
use synra_protocol::PluginId;
use synra_protocol::error::ErrorCode;
use super::super::{Registry, installed, signed_source};
use super::super::super::Runtime;
use synra_control::Kernel as _;

fn answer(client: &mut Client, request: &Request) -> serde_json::Value {
    match client.ask(request).expect("control response") {
        Response::Ok { value } => value,
        other => panic!("request {request:?}: {other:?}"),
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
