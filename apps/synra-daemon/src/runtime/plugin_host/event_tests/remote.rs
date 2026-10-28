use super::*;
use std::net::{TcpListener, TcpStream};
use synra_core::plugin_events::{REMOTE_RECEIPT_EVENT, RemoteAdmission, answer_remote_event};
use synra_core::{
    PeerLink,
    peer::{
        LocalPeer,
        authenticated::{AuthenticatedPeer, RequestAuthority},
    },
};
use synra_protocol::{
    DeviceId,
    envelope::{Envelope, OutboundSpec},
    event::EventName,
    session::PlatformKind,
};
use synra_testkit::authentication::NetworkFixture;

const SOURCE: &str = "00000000-0000-4000-8000-000000000002";
const TIMEOUT: Duration = Duration::from_secs(5);

struct RemoteRig {
    set: Arc<Mutex<PluginSet>>,
    service: Arc<synra_core::plugin_events::EventService>,
    client: PeerLink,
    server: PeerLink,
    plugin: EventPlugin,
    target: NetworkFixture,
    source: NetworkFixture,
}

impl Drop for RemoteRig {
    fn drop(&mut self) {
        self.service.stop();
        wait(|| !self.service.report().worker_running);
    }
}

fn peer(fixture: &NetworkFixture) -> AuthenticatedPeer {
    let id = fixture.credentials.public_identity().device_id();
    AuthenticatedPeer::new(
        Arc::clone(&fixture.shared_db),
        Arc::clone(&fixture.credentials),
        LocalPeer::new(id, "events", PlatformKind::Desktop, "1.0.0"),
    )
    .unwrap()
}

fn connected(source: &NetworkFixture, target: &NetworkFixture) -> (PeerLink, PeerLink) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let client = peer(source);
    let server = peer(target);
    let target_now = target.now_ms / 1000;
    std::thread::scope(|scope| {
        let accepting = scope.spawn(|| {
            let until = Instant::now() + TIMEOUT;
            let socket: TcpStream = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < until, "accept deadline");
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            server.accept(socket, 1, target_now, TIMEOUT).unwrap().0
        });
        let outgoing = client
            .dial(
                address,
                target.credentials.public_identity().device_id(),
                1,
                source.now_ms / 1000,
                TIMEOUT,
            )
            .unwrap()
            .0;
        (outgoing, accepting.join().unwrap())
    })
}

impl RemoteRig {
    fn new() -> Self {
        let source_id: DeviceId = SOURCE.parse().unwrap();
        let target_id: DeviceId = DEVICE.parse().unwrap();
        let source = NetworkFixture::new(source_id, target_id, "Source").unwrap();
        let target = NetworkFixture::new(target_id, source_id, "Target").unwrap();
        let plugin = EventPlugin::receiver(None).unwrap();
        plugin.persist(&target.shared_db.lock()).unwrap();
        let host = Arc::new(KernelHost::new(Arc::clone(&target.shared_db), "test"));
        let service = host.events();
        let engine =
            synra_plugin_host::engine::WasmtimeBackend::new(BackendKind::WasmtimeCranelift)
                .unwrap();
        let set = PluginSet::new(Backend::new(Arc::new(engine)), host)
            .with_event_delivery(Arc::clone(&service))
            .into_shared()
            .unwrap();
        load(&mut set.lock(), &plugin);
        let (client, server) = connected(&source, &target);
        Self {
            set,
            service,
            client,
            server,
            plugin,
            target,
            source,
        }
    }

    fn request(&self, event: &str, payload: &serde_json::Value) -> Envelope {
        Envelope::outbound(
            OutboundSpec {
                event: EventName::parse(event).unwrap(),
                from: SOURCE.parse().unwrap(),
                target: DEVICE.parse().unwrap(),
                trace_id: TraceId::new(),
                sent_at_ms: self.source.now_ms as i64,
                ttl_ms: Some(5000),
            },
            Some(payload),
        )
        .unwrap()
    }

    fn receive(&mut self, request: &Envelope) -> (Envelope, RequestAuthority) {
        self.client.send(request).unwrap();
        let received = self.server.receive().unwrap();
        let authority = self.server.request_authority().unwrap();
        (received, authority)
    }

    fn roundtrip(&mut self, request: &Envelope) -> RemoteAdmission {
        let (received, authority) = self.receive(request);
        let reply = answer_remote_event(
            Some(&self.service),
            &received,
            &authority,
            self.target.now_ms as i64,
        )
        .unwrap();
        self.server.send(&reply).unwrap();
        let response = self.client.receive().unwrap();
        assert_eq!(response.reply_to, Some(request.request_id));
        assert_eq!(response.trace_id, request.trace_id);
        assert_eq!(response.event.as_str(), REMOTE_RECEIPT_EVENT);
        assert_eq!(response.from, request.target);
        assert_eq!(response.target, request.from);
        serde_json::from_str(response.payload_str().unwrap()).unwrap()
    }

    fn stored(&self, key: &str) -> Option<String> {
        self.target
            .shared_db
            .lock()
            .storage_get(self.plugin.id.as_str(), key)
            .unwrap()
    }
}

#[test]
fn real_tls_admission_is_nonblocking_and_guest_context_keeps_authenticated_identity() {
    let mut rig = RemoteRig::new();
    let payload = serde_json::json!({"text":"中文🖱️","from":"forged","senderPluginId":"@other/plugin","traceId":"fake"});
    let request = rig.request(EVENT, &payload);
    let runtime = Arc::clone(&rig.set);
    let busy = runtime.lock();
    assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
    assert!(rig.stored("received").is_none());
    assert_eq!(rig.service.report().delivered, 0);
    drop(busy);
    wait(|| rig.service.report().delivered == 1);
    let context: serde_json::Value =
        serde_json::from_str(&rig.stored("received").unwrap()).unwrap();
    assert_eq!(context["payload"], payload);
    assert_eq!(context["from"], SOURCE);
    assert_eq!(context["senderPluginId"], "@acme/emitter");
    assert_eq!(context["requestId"], request.request_id.to_string());
    assert_eq!(context["traceId"], request.trace_id.to_string());
    assert_eq!(rig.stored("calls").as_deref(), Some("1"));
}

#[test]
fn identical_remote_requests_acknowledge_once_without_reexecuting_a_guest() {
    let mut rig = RemoteRig::new();
    let request = rig.request(EVENT, &serde_json::json!({"text":"one"}));
    assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
    wait(|| rig.service.report().delivered == 1);
    assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
    let mut conflict = rig.request(EVENT, &serde_json::json!({"text":"other"}));
    conflict.request_id = request.request_id;
    let RemoteAdmission::Refused { error } = rig.roundtrip(&conflict) else {
        panic!("reused ID admitted");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    let barrier = rig.request(EVENT, &serde_json::json!({"text":"barrier"}));
    assert!(matches!(rig.roundtrip(&barrier), RemoteAdmission::Accepted));
    wait(|| {
        rig.stored("received").is_some_and(|context| {
            let value: serde_json::Value = serde_json::from_str(&context).unwrap();
            value["payload"]["text"] == "barrier"
        })
    });
    assert_eq!(rig.stored("calls").as_deref(), Some("2"));
}

#[test]
fn queue_pressure_refuses_without_remembering_an_unadmitted_request() {
    let mut rig = RemoteRig::new();
    let runtime = Arc::clone(&rig.set);
    let busy = runtime.lock();
    let first = rig.request(EVENT, &serde_json::json!({"text":"first"}));
    assert!(matches!(rig.roundtrip(&first), RemoteAdmission::Accepted));
    wait(|| rig.service.report().pending == 0);
    for _ in 0..synra_core::plugin_events::MAX_PENDING {
        let request = rig.request(EVENT, &serde_json::json!({"text":"queued"}));
        assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
    }
    let refused = rig.request(EVENT, &serde_json::json!({"text":"retry"}));
    let RemoteAdmission::Refused { error } = rig.roundtrip(&refused) else {
        panic!("queue overflow admitted");
    };
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(
        rig.service.report().pending,
        synra_core::plugin_events::MAX_PENDING
    );
    drop(busy);
    let mut errors = Vec::new();
    wait(|| {
        let report = rig.service.report();
        for error in report.recent.iter().filter_map(|entry| entry.error) {
            if !errors.contains(&error) {
                errors.push(error);
            }
        }
        report.delivered + report.refused >= 129
    });
    let report = rig.service.report();
    assert_eq!(report.delivered, 129, "refusals: {errors:?}");
    assert!(matches!(rig.roundtrip(&refused), RemoteAdmission::Accepted));
    wait(|| rig.service.report().delivered == 130);
    assert_eq!(rig.stored("calls").as_deref(), Some("130"));
}

#[test]
fn receipt_window_refuses_new_ids_without_evicting_live_deduplication_entries() {
    let mut rig = RemoteRig::new();
    let first = rig.request("_plugin.@acme/emitter.unhandled", &serde_json::json!({}));
    assert!(matches!(rig.roundtrip(&first), RemoteAdmission::Accepted));
    let deadline = Instant::now() + Duration::from_secs(30);
    for _ in 1..synra_core::plugin_events::MAX_REMOTE_RECEIPTS {
        assert!(Instant::now() < deadline, "receipt test budget");
        let request = rig.request("_plugin.@acme/emitter.unhandled", &serde_json::json!({}));
        assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
        wait(|| rig.service.report().pending < 64);
    }
    let overflow = rig.request("_plugin.@acme/emitter.unhandled", &serde_json::json!({}));
    let RemoteAdmission::Refused { error } = rig.roundtrip(&overflow) else {
        panic!("receipt cache grew without bound");
    };
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert_eq!(error.details.unwrap()["kind"], "receiptWindowFull");
    assert!(matches!(rig.roundtrip(&first), RemoteAdmission::Accepted));
    wait(|| rig.service.report().unhandled == 1024);
    assert!(rig.stored("received").is_none());
}

#[test]
fn peer_and_plugin_revocation_while_queued_prevent_real_guest_execution() {
    for revoke_peer in [true, false] {
        let mut rig = RemoteRig::new();
        let request = rig.request(EVENT, &serde_json::json!({"text":"private"}));
        let runtime = Arc::clone(&rig.set);
        let busy = runtime.lock();
        assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
        if revoke_peer {
            assert!(rig.target.unpair_device(SOURCE).unwrap());
        } else {
            rig.target
                .record_grants(
                    rig.plugin.id.as_str(),
                    &[(format!("event:subscribe:{EVENT}"), false)],
                    2,
                    &synra_plugin_api::manifest_digest(&rig.plugin.manifest),
                )
                .unwrap();
        }
        drop(busy);
        wait(|| rig.service.report().refused > 0);
        assert!(rig.stored("received").is_none());
        assert!(
            rig.service
                .report()
                .recent
                .iter()
                .any(|entry| entry.error == Some(ErrorCode::CapabilityDenied))
        );
    }
}

#[test]
fn reconsent_does_not_revive_queued_work_or_acknowledge_old_request_ids_as_new_work() {
    let mut rig = RemoteRig::new();
    let request = rig.request(EVENT, &serde_json::json!({"text":"stale"}));
    let runtime = Arc::clone(&rig.set);
    let busy = runtime.lock();
    assert!(matches!(rig.roundtrip(&request), RemoteAdmission::Accepted));
    assert!(rig.target.unpair_device(SOURCE).unwrap());
    // Seed a new explicitly approved fixture generation, without claiming to test first-pairing UI.
    let now = synra_store::sqlite::now_ms();
    let attempt = synra_store::sqlite::PeerTrustAttempt {
        request_id: synra_protocol::RequestId::new().to_string(),
        local_id: DEVICE.to_owned(),
        local_certificate: rig
            .target
            .credentials
            .public_identity()
            .certificate_der()
            .to_vec(),
        peer_id: SOURCE.to_owned(),
        peer_certificate: rig
            .source
            .credentials
            .public_identity()
            .certificate_der()
            .to_vec(),
        binding: [8; 32],
        expires_at_ms: now + 60_000,
    };
    assert!(rig.target.claim_peer_trust(&attempt, now, 256).unwrap());
    assert!(rig.target.store_peer_consent(&attempt, now).unwrap());
    assert!(rig.target.activate_peer_trust(&attempt, now).unwrap());
    drop(busy);
    wait(|| rig.service.report().refused == 1);
    assert!(rig.stored("received").is_none());
    (rig.client, rig.server) = connected(&rig.source, &rig.target);
    let RemoteAdmission::Refused { error } = rig.roundtrip(&request) else {
        panic!("old request revived");
    };
    assert_eq!(error.code, ErrorCode::CapabilityDenied);
    let fresh = rig.request(EVENT, &serde_json::json!({"text":"fresh"}));
    assert!(matches!(rig.roundtrip(&fresh), RemoteAdmission::Accepted));
    wait(|| rig.service.report().delivered == 1);
    assert_eq!(rig.stored("calls").as_deref(), Some("1"));
}

#[test]
fn malformed_payload_expiry_and_missing_engine_return_classified_admission_refusals() {
    let mut rig = RemoteRig::new();
    let request = rig.request(EVENT, &serde_json::json!({"text":"private"}));
    let (received, authority) = rig.receive(&request);
    for (mut invalid, expected) in [
        (
            rig.request(EVENT, &serde_json::json!(["private"])),
            ErrorCode::InvalidArgument,
        ),
        (
            rig.request("_synra.intent.invoke", &serde_json::json!({})),
            ErrorCode::InvalidArgument,
        ),
        (
            {
                let mut expired = received.clone();
                expired.ttl_ms = Some(0);
                expired
            },
            ErrorCode::Timeout,
        ),
        (
            {
                let mut reply = received.clone();
                reply.reply_to = Some(received.request_id);
                reply
            },
            ErrorCode::InvalidArgument,
        ),
    ] {
        invalid.request_id = synra_protocol::RequestId::new();
        assert_eq!(
            rig.service
                .receive_remote(&invalid, &authority)
                .unwrap_err()
                .code,
            expected
        );
    }
    let unavailable =
        answer_remote_event(None, &received, &authority, rig.target.now_ms as i64).unwrap();
    let answer: RemoteAdmission = serde_json::from_str(unavailable.payload_str().unwrap()).unwrap();
    assert!(
        matches!(answer, RemoteAdmission::Refused { error } if error.code == ErrorCode::Unsupported)
    );
    assert_eq!(rig.service.report().pending, 0);
    assert!(rig.stored("received").is_none());
}
