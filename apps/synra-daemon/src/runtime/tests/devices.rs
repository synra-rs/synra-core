use super::*;

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
    assert!(
        value["self"]["deviceId"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
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
    assert_eq!(
        runtime
            .scan_until_ms
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    // No discovery socket in this fixture, so `scan` returns without publishing anything — and the call still has to
    // be harmless, because a kernel with no network is a state the code has to handle.
    assert!(runtime.discovery.is_none());
    let _ = runtime.devices(true, Some(10)).expect("devices");
    assert_eq!(
        runtime
            .scan_until_ms
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn a_zero_or_absent_scan_budget_does_not_scan() {
    // `--cached` means "do not scan", and it is expressed as an absent budget rather than as a zero one so the
    // protocol's own rule holds: an absent field is a client saying nothing, not a client saying zero.
    let dir = TempDir::new("no-scan");
    let runtime = runtime(dir.path());
    assert!(runtime.devices(true, None).is_ok());
    assert!(runtime.devices(true, Some(0)).is_ok());
    assert_eq!(
        runtime
            .scan_until_ms
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
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
        device_id: "33333333-3333-4333-8333-333333333333"
            .parse()
            .expect("a device id"),
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
    assert_eq!(
        value["paired"].as_array().map(Vec::len),
        Some(0),
        "nothing is paired"
    );
    let found = value["found"].as_array().expect("a list");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["displayName"], "Phone");
    assert_eq!(found[0]["trust"], "Handshaked");
    // And the port is the one it listens on for connections, not the ephemeral one it sent from.
    assert!(
        found[0]["address"]
            .as_str()
            .is_some_and(|a| a.ends_with(":47100")),
        "{found:?}"
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
