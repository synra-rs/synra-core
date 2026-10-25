// ── A real transfer, so the transfer metrics have evidence ──────────────────────────────────────

use super::*;

const SENDER: &str = "22222222-2222-4222-8222-222222222222";
const RECEIVER: &str = "11111111-1111-4111-8111-111111111111";

fn sender(dir: &Path) -> (Runtime, synra_testkit::authentication::NetworkFixture) {
    let fixture = synra_testkit::authentication::NetworkFixture::new(
        SENDER.parse().unwrap(),
        RECEIVER.parse().unwrap(),
        "Sender",
    )
    .unwrap();
    let runtime = runtime_over(dir, std::sync::Arc::clone(&fixture.shared_db));
    let profile = synra_core::LocalPeer::new(
        runtime.identity.device_id,
        runtime.identity.display_name.clone(),
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0-test",
    );
    let network = synra_core::peer::authenticated::AuthenticatedPeer::new(
        std::sync::Arc::clone(&fixture.shared_db),
        std::sync::Arc::clone(&fixture.credentials),
        profile,
    )
    .unwrap();
    runtime.host.lock().configure_network(Ok(network));
    (runtime, fixture)
}

fn listening(
    id: &str,
    name: &str,
) -> (
    std::sync::Arc<parking_lot::Mutex<Host>>,
    std::net::SocketAddr,
    synra_testkit::authentication::NetworkFixture,
) {
    let fixture = synra_testkit::authentication::NetworkFixture::new(
        id.parse().unwrap(),
        SENDER.parse().unwrap(),
        name,
    )
    .unwrap();
    let identity = Identity::load(&fixture, "test", 1_000).unwrap();
    let local = synra_core::LocalPeer::new(
        identity.device_id,
        name,
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0-test",
    );
    let network = synra_core::peer::authenticated::AuthenticatedPeer::new(
        std::sync::Arc::clone(&fixture.shared_db),
        std::sync::Arc::clone(&fixture.credentials),
        local.clone(),
    )
    .unwrap();
    let mut host = Host::new(identity, local);
    host.configure_network(Ok(network));
    let address = synra_core::listener::bind(&mut host, 0).unwrap();
    host.listen_nonblocking().unwrap();
    (
        std::sync::Arc::new(parking_lot::Mutex::new(host)),
        address,
        fixture,
    )
}

fn route(runtime: &Runtime, address: std::net::SocketAddr) {
    let profile = synra_core::LocalPeer::new(
        RECEIVER.parse().unwrap(),
        "Receiver",
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0-test",
    );
    runtime.host.lock().heard(
        &profile.announcement(address.port()),
        address,
        synra_store::sqlite::now_ms(),
    );
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
        synra_plugin_host::Backend::new(std::sync::Arc::new(
            synra_plugin_host::ScriptedBackend::new(),
        )),
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
    let (runtime, _sender_fixture) = sender(dir.path());
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
    let (listener, address, _receiver_fixture) =
        listening("11111111-1111-4111-8111-111111111111", "Laptop");
    let sending_host = std::sync::Arc::clone(&runtime.host);
    let served = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // The guard is dropped before the handshake: `handle_within` locks the same host, and holding it here
            // would be one thread asking for a mutex it already holds — the failure that looks like a silent peer.
            let taken = listener.lock().try_accept();
            match taken {
                Ok(Some(stream)) => {
                    let offer: std::sync::Arc<synra_core::inbound::OfferCallback> =
                        std::sync::Arc::new(move |_| {
                            assert!(
                                sending_host.try_lock().is_some(),
                                "file IO must not hold the sender host lock"
                            );
                            synra_core::inbound::OfferDecision::Accept
                        });
                    let progress: std::sync::Arc<synra_core::listener::ProgressCallback> =
                        std::sync::Arc::new(|_| {});
                    let cancel: std::sync::Arc<synra_core::listener::CancelCallback> =
                        std::sync::Arc::new(|_| false);
                    return synra_core::listener::handle_within_with(
                        &listener,
                        stream,
                        inbox.path(),
                        std::time::Duration::from_secs(5),
                        &test_desk(),
                        &test_router(),
                        &synra_core::listener::no_answer(),
                        &progress,
                        &offer,
                        &cancel,
                        &synra_core::listener::no_kernel_events(),
                    );
                }
                Ok(None) => {}
                Err(error) => panic!("the listener could not accept: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no connection arrived"
            );
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
    route(&runtime, dial_to);
    let answer = runtime.send_file(RECEIVER, &source.to_string_lossy());
    assert!(answer.is_ok(), "the send failed: {answer:?}");
    // ★ 监听端线程交回它服务过的那条连接，而这次连接上有一个真的落了地的文件 ——
    // 第 146 轮发现「收到包的那一刻没有可写的地方」，这是把那个值送到有地方可写的人手上的第一步。
    let served = served.join().expect("the server thread finished");
    assert_eq!(
        served.finished.len(),
        1,
        "the finished transfer was not handed back: {served:?}"
    );
    assert_eq!(served.finished[0].byte_length, 4_096);
    // 而它不是插件包 —— 发送的是一份附件。
    assert!(served.finished[0].bundle.is_none(), "{served:?}");
    // ★ 而它带着发送方 —— 逐条带上，因为「谁发的这个文件」是关于**文件**的事实，
    // 而 `Served::peer` 是关于**连接**的。
    assert_eq!(
        served.finished[0].peer,
        served.peer.expect("a handshaked peer")
    );

    let snapshot = runtime.metrics.snapshot();
    assert!(
        snapshot.get("transfer_bytes{kind=attachment}").is_some(),
        "the size of a completed transfer is not recorded"
    );
    assert!(
        snapshot
            .get("transfer_duration_ms{kind=attachment}")
            .is_some(),
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
    let (runtime, _sender_fixture) = sender(dir.path());
    let source = dir.path().join("plugin.wasm");
    std::fs::write(&source, b"\0asm\x01\0\0\0an artifact").expect("a file to send");

    runtime
        .host
        .lock()
        .set_flags(synra_core::peer::Flags::no_timeout());
    let inbox = TempDir::new("send-bundle-inbox");
    let (listener, address, _receiver_fixture) =
        listening("11111111-1111-4111-8111-111111111111", "Laptop");
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
            assert!(
                std::time::Instant::now() < deadline,
                "no connection arrived"
            );
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
    route(&runtime, dial_to);
    let answer = runtime.send_bundle(RECEIVER, &source.to_string_lossy(), "@acme/chat", "1.2.0");
    assert!(answer.is_ok(), "the send failed: {answer:?}");

    let served = served.join().expect("the server thread finished");
    assert_eq!(served.finished.len(), 1, "{served:?}");
    // ★ 而它到了对端**作为插件包**，带着它的标识 —— 这是授权安装的那一步。
    assert_eq!(
        served.finished[0].bundle.as_ref().map(ToString::to_string),
        Some("@acme/chat".to_owned()),
        "a bundle arrived as something else"
    );

    // ★ And the sender files the size and duration under `bundle`, not `attachment`. This was hardcoded, so the two
    // ends disagreed about what crossed the wire and a bundle was invisible in the attachment series.
    let snapshot = runtime.metrics.snapshot();
    assert!(
        snapshot.get("transfer_bytes{kind=bundle}").is_some(),
        "a bundle was measured as an attachment"
    );
    assert!(
        snapshot
            .get("transfer_throughput_bps{kind=bundle}")
            .is_some(),
        "the throughput of a completed bundle is not recorded"
    );
    assert!(
        snapshot.get("transfer_bytes{kind=attachment}").is_none(),
        "a bundle contributed to the attachment series"
    );

    // ★ 而**发送端**也记下了「对端现在持有这个版本」—— 与接收端那一半（`sync_records`）对称。
    // 版本在这里是 `1.2.0`，而接收端那一行是空串：接收端只知道传输的元数据里有什么，
    // 而发送端知道它**推的是哪个版本**。两行回答的是同一个问题的两侧。
    let held = runtime.db().sync_records().expect("reads");
    assert_eq!(
        held.len(),
        1,
        "the sender did not record what the peer holds: {held:?}"
    );
    assert_eq!(held[0].plugin_id, "@acme/chat");
    assert_eq!(held[0].peer_device, "11111111-1111-4111-8111-111111111111");
    assert_eq!(held[0].version, "1.2.0");
    assert!(
        !held[0].digest.is_empty(),
        "the digest the receiver confirmed is missing"
    );
}
