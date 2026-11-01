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



    fn stored(&self, key: &str) -> Option<String> {
        self.target
            .shared_db
            .lock()
            .storage_get(self.plugin.id.as_str(), key)
            .unwrap()
    }
}







