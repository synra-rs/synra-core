use super::*;
use crate::host::{DialConfig, dial_peer};
use crate::{Flags, Host, Identity, LocalPeer};
use parking_lot::Mutex;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
use synra_protocol::ids::SessionId;
use synra_protocol::session::PlatformKind;

mod controller;

#[test]
fn deliberate_host_shutdown_waits_for_native_button_release() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    assert!(h.receiver.shutdown());
    assert_eq!(h.effects.lock().last(), Some(&Effect::Released));
    h.close();
}

struct TestPolicy {
    allowed: AtomicBool,
    revision: AtomicI64,
    dial: DialConfig,
    address: SocketAddr,
}

impl Policy for TestPolicy {
    fn authorize(&self, _: DeviceId, _: &PluginId, _: bool) -> Result<i64, String> {
        if !self.allowed.load(Ordering::Acquire) {
            return Err("revoked".to_owned());
        }
        Ok(self.revision.load(Ordering::Acquire))
    }
    fn connect(&self, peer: DeviceId) -> Result<PeerLink, String> {
        dial_peer(
            &self.dial,
            Flags::production(),
            self.address,
            peer,
            crate::reading_millis(synra_store::sqlite::now_ms()),
        )
        .map(crate::Dialled::into_link)
        .map_err(|error| error.to_string())
    }
    fn peer_name(&self, _: DeviceId) -> String {
        "Test phone".to_owned()
    }
}

#[derive(Debug, PartialEq)]
enum Effect {
    Created,
    Apply(Command),
    Released,
}

struct RecordingPointer(Arc<Mutex<Vec<Effect>>>);
impl synra_platform::pointer::Pointer for RecordingPointer {
    fn apply(&mut self, command: Command) -> Result<(), String> {
        self.0.lock().push(Effect::Apply(command));
        Ok(())
    }
    fn release(&mut self) -> Result<(), String> {
        self.0.lock().push(Effect::Released);
        Ok(())
    }
}

fn host(name: &str) -> (Host, synra_testkit::fixtures::NetworkFixture) {
    let id = DeviceId::new();
    let db = synra_testkit::fixtures::NetworkFixture::unpaired(id, name).unwrap();
    let identity = Identity::load(&db, "test", synra_store::sqlite::now_ms()).unwrap();
    let peer = LocalPeer::new(id, name, PlatformKind::Desktop, "0.1.0");
    (Host::new(identity, peer), db)
}

struct Harness {
    link: PeerLink,
    receiver: Arc<Receiver>,
    notifications: mpsc::Receiver<Option<Snapshot>>,
    effects: Arc<Mutex<Vec<Effect>>>,
    policy: Arc<TestPolicy>,
    server: std::thread::JoinHandle<()>,
    control: SessionId,
}

impl Harness {
    fn start() -> Self {
        let (mut server, server_db) = host("Computer");
        let (client, client_db) = host("Phone");
        let address = server
            .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        server.listen_nonblocking().unwrap();
        let peer = server.device_id();
        let (dial, _) = client.dialling_parts();
        let policy = Arc::new(TestPolicy {
            allowed: AtomicBool::new(true),
            revision: AtomicI64::new(7),
            dial,
            address,
        });
        let effects = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&effects);
        let (notify, notifications) = mpsc::channel();
        let receiver = Arc::new(Receiver::new(
            policy.clone(),
            Arc::new(move || {
                recorded.lock().push(Effect::Created);
                Ok(Box::new(RecordingPointer(Arc::clone(&recorded))))
            }),
            Arc::new(move |state| {
                let _ = notify.send(state);
            }),
        ));
        server.set_input_receiver(Arc::clone(&receiver));
        let server = std::thread::spawn(move || {
            let _db_guard = server_db;
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                if let Some(stream) = server.try_accept().unwrap() {
                    break stream;
                }
                assert!(Instant::now() < deadline, "no incoming connection");
                std::thread::sleep(Duration::from_millis(5));
            };
            let (parts, flags) = server.dialling_parts();
            let now = crate::reading_millis(synra_store::sqlite::now_ms());
            let accepted = parts.accept_stream(stream, flags, now).unwrap();
            let mut link = server.adopt(accepted, now).unwrap();
            link.set_read_timeout(Some(Duration::from_secs(3)));
            let request = link.receive().unwrap();
            let host = crate::host::shared(server);
            assert!(serve_if_requested(&host, &mut link, &request));
        });
        let link = policy.connect(peer).unwrap();
        drop(client_db);
        let mut harness = Self {
            link,
            receiver,
            notifications,
            effects,
            policy,
            server,
            control: SessionId::new(),
        };
        harness.link.set_read_timeout(Some(Duration::from_secs(3)));
        let open = wire::Open {
            control_id: harness.control,
            plugin_id: PluginId::parse("@synra-plugin/touchpad").unwrap(),
        };
        wire::send(&mut harness.link, wire::OPEN, &open).unwrap();
        harness
    }

    fn pending(&self) -> Snapshot {
        self.notifications
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap()
    }

    fn approve(&mut self) -> wire::Accepted {
        let pending = self.pending();
        assert_eq!(pending.phase, Phase::Pending);
        assert!(
            self.effects.lock().is_empty(),
            "no native adapter before consent"
        );
        assert!(self.receiver.decide(pending.session, true));
        let response = self.link.receive().unwrap();
        assert_eq!(response.event.as_str(), wire::ACCEPT);
        wire::read(&response).unwrap()
    }

    fn packet(
        &mut self,
        accepted: &wire::Accepted,
        sequence: u64,
        commands: Vec<Command>,
    ) -> String {
        wire::send(
            &mut self.link,
            wire::PACKET,
            &wire::Packet {
                session: accepted.session,
                generation: accepted.generation,
                sequence,
                commands,
            },
        )
        .unwrap();
        self.link.receive().unwrap().event.as_str().to_owned()
    }

    fn close(mut self) {
        let _ = wire::send(&mut self.link, wire::CANCEL, &self.control);
        drop(self.link);
        self.server.join().unwrap();
    }
}

#[test]
fn real_tcp_input_waits_for_consent_then_executes_in_order_and_releases() {
    let mut h = Harness::start();
    let accepted = h.approve();
    let commands = vec![
        Command::Move { dx: 4.0, dy: -3.0 },
        Command::LeftClick,
        Command::RightClick,
        Command::Scroll { dx: 0.0, dy: 40.0 },
        Command::LeftDown,
        Command::Move { dx: 2.0, dy: 0.0 },
        Command::LeftUp,
    ];
    assert_eq!(h.packet(&accepted, 1, commands.clone()), wire::ACK);
    let effects = Arc::clone(&h.effects);
    h.close();
    let expected: Vec<_> = [Effect::Created]
        .into_iter()
        .chain(commands.into_iter().map(Effect::Apply))
        .chain([Effect::Released])
        .collect();
    assert_eq!(*effects.lock(), expected);
}

#[test]
fn refusing_consent_never_initializes_native_input() {
    let mut h = Harness::start();
    let pending = h.pending();
    assert!(h.receiver.decide(pending.session, false));
    assert_eq!(h.link.receive().unwrap().event.as_str(), wire::ERROR);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert!(effects.lock().is_empty());
}

#[test]
fn cancelling_before_consent_removes_the_pending_request_without_input() {
    let h = Harness::start();
    let _ = h.pending();
    let receiver = Arc::clone(&h.receiver);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(receiver.snapshot().unwrap().phase, Phase::Ended);
    assert!(effects.lock().is_empty());
}

#[test]
fn a_replayed_click_is_refused_before_the_os_and_ends_the_session() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftClick]), wire::ACK);
    assert_eq!(
        h.packet(&accepted, 1, vec![Command::LeftClick]),
        wire::ERROR
    );
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(
        effects
            .lock()
            .iter()
            .filter(|effect| **effect == Effect::Apply(Command::LeftClick))
            .count(),
        1
    );
}

#[test]
fn revocation_releases_a_drag_even_without_more_phone_input() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    h.policy.revision.fetch_add(1, Ordering::AcqRel);
    assert_eq!(h.link.receive().unwrap().event.as_str(), wire::ERROR);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
}

#[test]
fn a_quiet_but_open_tcp_connection_cannot_keep_a_drag_held() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    let response = h.link.receive().unwrap();
    assert_eq!(response.event.as_str(), wire::ERROR);
    assert!(
        wire::read::<String>(&response)
            .unwrap()
            .contains("lease expired")
    );
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
}

#[test]
fn host_stop_releases_before_a_late_packet_can_execute() {
    let mut h = Harness::start();
    let accepted = h.approve();
    assert_eq!(h.packet(&accepted, 1, vec![Command::LeftDown]), wire::ACK);
    h.receiver.stop(accepted.session);
    // The receiver is polling without requiring a final message from the controller.
    assert_eq!(h.link.receive().unwrap().event.as_str(), wire::ERROR);
    let effects = Arc::clone(&h.effects);
    h.close();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
}
