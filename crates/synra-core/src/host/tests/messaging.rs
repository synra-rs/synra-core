use std::sync::Arc;
use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::EventName;
use synra_protocol::handshake::PROTOCOL_VERSION;
use synra_protocol::session::PlatformKind;
use crate::sessions::LinkState;
use super::super::HostError;
use super::{A, B, device, host, network_now, listening};

#[test]
fn an_envelope_travels_between_two_connected_hosts() {
    // The whole path: dial, handshake, session, envelope, and a session recorded on the receiving side.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (client, _client_db) = host(B, "Phone");
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut client = client.with_metrics(Arc::clone(&recorder));

    let serving = std::thread::spawn(move || {
        let (mut link, _) = server.accept(network_now()).expect("accepts");
        let envelope = link.receive().expect("receives");
        (envelope, server)
    });

    let mut link = client
        .dial(address, device(A), network_now())
        .expect("dials");
    let envelope = Envelope::outbound(
        OutboundSpec {
            event: EventName::parse("device.ping").expect("a name"),
            target: device(A),
            from: device(B),
            trace_id: synra_protocol::ids::TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&serde_json::Value>,
    )
    .expect("builds");
    client.send(&mut link, &envelope).expect("sends");

    let (received, server) = serving.join().expect("finished");
    assert_eq!(received.event.as_str(), "device.ping");
    assert_eq!(received.from, device(B));
    assert_eq!(client.sent(), 1);
    // ★ 而同一个事实现在也说得出**说了什么** —— `frames_sent_total{event}`。
    // `sent()` 回答「说了多少」，而排查时要问的是「说了哪一类」。
    assert_eq!(
        recorder
            .snapshot()
            .get("frames_sent_total{event=device.ping}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the frame was not counted by its event"
    );
    // ★ 而链路本身也是一个事实：`links_opened_total`。客户端的这一条是它拨号时开的，
    // 而 `adopt` 是拨入与接入**共同**经过的地方 —— 所以同一个计数也覆盖服务端那一侧。
    assert_eq!(
        recorder.snapshot().get("links_opened_total"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the client's link was not counted"
    );
    // The receiving host recorded the session too, which is what makes the envelope attributable.
    assert_eq!(server.state_of(device(B)), Some(LinkState::Ready));
}

#[test]
fn text_travels_from_one_host_to_another() {
    // ★ The end-to-end path `synra send` takes: resolve what the user typed, dial the address the kernel knows, and
    // put a clipboard envelope on the link. Every piece has its own tests; what none of those can see is the sequence.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");

    let serving = std::thread::spawn(move || {
        let (mut link, _) = server.accept(network_now()).expect("accepts");
        let envelope = link.receive().expect("receives");
        let payload = envelope
            .payload
            .as_ref()
            .expect("a payload")
            .get()
            .to_owned();
        (envelope, payload, server)
    });

    // The client learns about the server the way it would on a network, then resolves it by name.
    let announcement = DeviceAnnouncement {
        device_id: device(A),
        display_name: "Laptop".to_owned(),
        protocol: PROTOCOL_VERSION,
        port: address.port(),
        platform: Some(PlatformKind::Desktop),
        app_version: None,
        features: Vec::new(),
    };
    client.heard(&announcement, address, 1_000);

    // ★ By name, which is what `--to Laptop` does, and the identifier is what it resolves to.
    let resolved = client.resolve("Laptop").expect("resolves");
    assert_eq!(resolved, device(A));
    assert_eq!(client.address_of(resolved), Some(address));

    let envelope = crate::messaging::text_to(
        client.device_id(),
        resolved,
        "hello from the phone",
        synra_protocol::ids::TraceId::new(),
        1_000,
    )
    .expect("builds");

    let mut link = client
        .dial(address, device(A), network_now())
        .expect("dials");
    client.send(&mut link, &envelope).expect("sends");

    let (received, payload, _server) = serving.join().expect("finished");
    assert_eq!(
        received.event.as_str(),
        synra_protocol::event::builtin::CLIPBOARD_RECEIVED
    );
    assert_eq!(received.from, device(B));
    // And the payload is the shape the receiver's own type parses.
    let parsed: crate::messaging::ClipboardText = serde_json::from_str(&payload).expect("parses");
    assert_eq!(parsed.text, "hello from the phone");
    assert_eq!(parsed.from_device_id, device(B));
}

#[test]
fn sending_on_a_link_the_host_has_no_session_for_is_refused() {
    // ★ A caller holding a link and a host that do not belong together is the case this refuses. Attributing an
    // envelope to the wrong session is a mistake with no symptom until the wrong device is blamed for something.
    let (mut server, _server_db, address) = listening(A, "Laptop");
    let (mut client, _client_db) = host(B, "Phone");
    let (mut other, _other_db) = host("33333333-3333-4333-8333-333333333333", "Tablet");

    let serving = std::thread::spawn(move || {
        server.accept(network_now()).expect("accepts");
    });
    let mut link = client
        .dial(address, device(A), network_now())
        .expect("dials");
    serving.join().expect("finished");

    // `other` has no session with A, so it will not send on a link that belongs to `client`.
    let envelope = Envelope::outbound(
        OutboundSpec {
            event: EventName::parse("device.ping").expect("a name"),
            target: device(A),
            from: other.device_id(),
            trace_id: synra_protocol::ids::TraceId::new(),
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&serde_json::Value>,
    )
    .expect("builds");

    match other.send(&mut link, &envelope) {
        Err(HostError::NoSession(id)) => assert_eq!(id, device(A)),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_received_frame_is_counted_by_its_event() {
    // ★ 这条测的是 `Host::count_frame_received` **本身**，而不是「它被调用过」。
    //
    // 2026-10-19 起，帧计数搬到了 `PeerLink`：它见到**每一帧**，包括拨号链路上绕过 Host 写出的那些。所以这条
    // 测试现在钉的是 Host 自己的方法（壳的接线测试用它证明记录器接上了），而不是生产路径 —— 生产路径的断言在
    // `link.rs` 的 `a_link_with_a_recorder_counts_the_frames_it_moves` 里，同时覆盖收与发两个方向。
    let (host, _db) = host(A, "Laptop");
    let recorder = Arc::new(synra_observe::metrics::RingRecorder::new());
    let mut host = host.with_metrics(Arc::clone(&recorder));

    host.count_frame_received("device.ping");

    assert_eq!(
        recorder
            .snapshot()
            .get("frames_received_total{event=device.ping}"),
        Some(&synra_observe::metrics::Value::Counter(1)),
        "the frame was not counted by its event"
    );
    // ★ 而它记的是**接收**那一侧而不是发送：两个方向是分开的方法，
    // 因为「说得比听到的多」与「听到的比说得多」是两种不同的处境。
    assert_eq!(
        recorder
            .snapshot()
            .get("frames_sent_total{event=device.ping}"),
        None,
        "receiving counted as sending"
    );
}
