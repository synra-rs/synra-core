use super::{Effect, RecordingPointer, TestPolicy, host};
use crate::input::{Command, Controller, Phase, Receiver, serve_if_requested};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
use synra_protocol::PluginId;

fn exercise(expire_ui: bool) {
    let (mut server, server_db) = host("Computer");
    let (phone, phone_db) = host("Phone");
    let peer = server.device_id();
    let address = server
        .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    server.listen_nonblocking().unwrap();
    let (dial, _) = phone.dialling_parts();
    let policy = Arc::new(TestPolicy {
        allowed: AtomicBool::new(true),
        revision: AtomicI64::new(1),
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
    let worker = std::thread::spawn(move || {
        let _db = server_db;
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            if let Some(stream) = server.try_accept().unwrap() {
                break stream;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        let (parts, flags) = server.dialling_parts();
        let now = crate::reading_millis(synra_store::sqlite::now_ms());
        let accepted = parts.accept_stream(stream, flags, now).unwrap();
        let mut link = server.adopt(accepted, now).unwrap();
        link.set_read_timeout(Some(Duration::from_secs(3)));
        let request = link.receive().unwrap();
        assert!(serve_if_requested(
            &crate::host::shared(server),
            &mut link,
            &request
        ));
    });
    let controller = Controller::new(policy.clone());
    let plugin = PluginId::parse("@synra-plugin/touchpad").unwrap();
    let request = |args: Value| -> Value {
        serde_json::from_str(&controller.request(&plugin, &args.to_string()).unwrap()).unwrap()
    };
    let state = request(json!({"op":"open","target":peer}));
    let session = state["session"].clone();
    assert_eq!(state["phase"], "pending");
    let pending = notifications
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(pending.phase, Phase::Pending);
    assert!(effects.lock().is_empty());
    let other = PluginId::parse("@other/plugin").unwrap();
    assert!(
        controller
            .request(
                &other,
                &json!({"op":"status","session":session}).to_string()
            )
            .is_err()
    );
    assert!(receiver.decide(pending.session, true));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if request(json!({"op":"status","session":session}))["phase"] == "active" {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    request(
        json!({"op":"frame","session":session,"commands":[{"kind":"leftDown"},{"kind":"move","dx":12,"dy":-4}]}),
    );
    loop {
        if effects
            .lock()
            .iter()
            .any(|effect| matches!(effect, Effect::Apply(Command::Move { .. })))
        {
            break;
        }
        assert!(Instant::now() < deadline);
        request(json!({"op":"status","session":session}));
        std::thread::sleep(Duration::from_millis(10));
    }
    if !expire_ui {
        policy.revision.store(2, Ordering::Release);
    }
    // No final release is sent. Either the source UI lease or grant generation must end both sides.
    worker.join().unwrap();
    assert_eq!(effects.lock().last(), Some(&Effect::Released));
    assert_eq!(
        request(json!({"op":"status","session":session}))["phase"],
        "ended"
    );
    drop(phone_db);
}

#[test]
fn controller_and_receiver_use_real_tcp_and_release_on_grant_change() {
    exercise(false);
}

#[test]
fn a_controller_without_visible_ui_cannot_keep_a_drag_alive() {
    exercise(true);
}

#[test]
fn cancelling_an_inflight_dial_never_opens_a_late_consent_prompt() {
    use crate::input::Policy;
    use synra_protocol::DeviceId;
    struct Delayed {
        inner: TestPolicy,
        started: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }
    impl Policy for Delayed {
        fn authorize(
            &self,
            peer: DeviceId,
            plugin: &PluginId,
            receiving: bool,
        ) -> Result<i64, String> {
            self.inner.authorize(peer, plugin, receiving)
        }
        fn peer_name(&self, peer: DeviceId) -> String {
            self.inner.peer_name(peer)
        }
        fn connect(&self, peer: DeviceId) -> Result<crate::PeerLink, String> {
            self.started.send(()).map_err(|e| e.to_string())?;
            self.resume
                .lock()
                .recv_timeout(Duration::from_secs(3))
                .map_err(|e| e.to_string())?;
            self.inner.connect(peer)
        }
    }
    let (mut server, server_db) = host("Computer");
    let (phone, phone_db) = host("Phone");
    let peer = server.device_id();
    let address = server
        .listen_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    server.listen_nonblocking().unwrap();
    let (dial, _) = phone.dialling_parts();
    let (started, waiting) = mpsc::channel();
    let (resume, gate) = mpsc::channel();
    let policy = Delayed {
        inner: TestPolicy {
            allowed: AtomicBool::new(true),
            revision: AtomicI64::new(1),
            dial,
            address,
        },
        started,
        resume: Mutex::new(gate),
    };
    let incoming = std::thread::spawn(move || {
        let _db = server_db;
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            if let Some(stream) = server.try_accept().unwrap() {
                break stream;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        let (dial, flags) = server.dialling_parts();
        let now = crate::reading_millis(synra_store::sqlite::now_ms());
        let accepted = dial.accept_stream(stream, flags, now).unwrap();
        let mut link = server.adopt(accepted, now).unwrap();
        link.set_read_timeout(Some(Duration::from_secs(3)));
        assert!(
            matches!(link.receive(), Err(crate::LinkError::Closed)),
            "a cancelled controller sent no input OPEN"
        );
    });
    let controller = Controller::new(Arc::new(policy));
    let plugin = PluginId::parse("@synra-plugin/touchpad").unwrap();
    controller
        .request(&plugin, &json!({"op":"open","target":peer}).to_string())
        .unwrap();
    waiting.recv_timeout(Duration::from_secs(3)).unwrap();
    controller.close_plugin(&plugin);
    resume.send(()).unwrap();
    incoming.join().unwrap();
    drop(phone_db);
}
