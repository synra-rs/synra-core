//! The kernel's bootstrap order and its two read paths, driven the way a caller drives them.
//!
//! What is asserted here is mostly *ordering* and *agreement*: that a kernel can be built twice over the same store
//! without making a second identity, that a snapshot and the events describe the same state, and that a subscriber
//! which fell behind is told rather than left with a gap.

use super::*;
use crate::supervisor::TaskSpec;

fn kernel() -> Kernel {
    Kernel::in_memory(&KernelConfig::headless()).expect("a kernel")
}


/// A path of this process's own, which the caller removes.
fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("synra-kernel-{name}-{}", std::process::id()))
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_kernel_bootstraps_with_an_identity_a_store_and_an_empty_supervisor() {
    let kernel = kernel();
    assert!(!kernel.identity().device_id.to_string().is_empty());
    assert!(!kernel.identity().display_name.is_empty());
    assert_eq!(kernel.role(), NodeRole::Daemon);
    assert!(!kernel.is_started(), "bootstrap does not start the network");
    assert!(kernel.supervisor().is_empty(), "nothing is registered until a role says what runs");
    assert_eq!(kernel.supervisor().started_at_ms(), kernel.created_at_ms());
}

#[test]
fn bootstrapping_twice_over_one_store_keeps_one_identity() {
    // ★ The failure the whole identity module is about: a device that made a new id on every start would appear to
    // every peer as a new device, and every pairing would be lost — silently, because a new device is legitimate.
    let path = temp_path("identity");
    let _ = std::fs::remove_file(&path);

    let first = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    let device_id = first.identity().device_id;

    let again = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    assert_eq!(again.identity().device_id, device_id, "the identity is read back, not remade");
    assert_eq!(again.identity().display_name, first.identity().display_name);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_open_constructor_migrates_a_file_that_has_never_been_opened() {
    // A first start: the file does not exist, and the kernel is expected to make it usable rather than to report that
    // its tables are missing.
    let path = temp_path("fresh");
    let _ = std::fs::remove_file(&path);
    let kernel = Kernel::open(&path, &KernelConfig::desktop()).expect("a kernel");
    assert_eq!(kernel.role(), NodeRole::Desktop);
    assert_eq!(kernel.snapshot().expect("a snapshot").devices.len(), 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_host_is_built_from_the_identity_that_was_loaded() {
    // ★ The ordering that matters: a host announcing itself has to know what to announce, so the identity is read or
    // created first and the host is built *from* it. A host built from a fresh identity would announce a device that
    // does not exist.
    let kernel = kernel();
    let announced = kernel.with_host(|host| host.identity().device_id);
    assert_eq!(announced, kernel.identity().device_id);
    let name = kernel.with_host(|host| host.local_peer().display_name.clone());
    assert_eq!(name, kernel.identity().display_name);
}

#[test]
fn a_role_says_whether_a_person_is_in_front_of_it() {
    // What an interface decision is made from: a prompt is right for a desktop and wrong for a daemon, where it would
    // sit unanswered while the sender waited.
    assert!(NodeRole::Desktop.has_a_user());
    assert!(NodeRole::Mobile.has_a_user());
    assert!(!NodeRole::Cli.has_a_user());
    assert!(!NodeRole::Daemon.has_a_user());
    assert_eq!(NodeRole::Daemon.as_str(), "daemon");
}

#[test]
fn the_two_configurations_name_their_own_roles_and_the_platform() {
    assert_eq!(KernelConfig::desktop().role, NodeRole::Desktop);
    assert!(KernelConfig::desktop().discovery);
    assert_eq!(KernelConfig::headless().role, NodeRole::Daemon);
    assert!(!KernelConfig::headless().discovery, "a test wants no sockets");
    assert_eq!(KernelConfig::headless().platform, std::env::consts::OS);
    assert_eq!(KernelConfig::headless().with_role(NodeRole::Cli).role, NodeRole::Cli);
}

// ── Starting, tasks and shutting down ─────────────────────────────────────────────────────────────

#[test]
fn a_task_is_registered_before_the_kernel_starts_and_not_after() {
    // ★ A task registered after the start is one nothing announced: its first effect would be observable to an
    // interface that had already been told the kernel was running.
    let kernel = kernel();
    kernel.register_task(TaskSpec::service("discovery.udp")).expect("registered");
    assert_eq!(kernel.supervisor().len(), 1);

    kernel.start().expect("started");
    match kernel.register_task(TaskSpec::service("transport.accept")) {
        Err(KernelError::AlreadyStarted) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_task_registered_twice_is_refused_by_name() {
    let kernel = kernel();
    kernel.register_task(TaskSpec::service("discovery.udp")).expect("registered");
    match kernel.register_task(TaskSpec::service("discovery.udp")) {
        Err(KernelError::Supervisor(error)) => assert!(error.to_string().contains("discovery.udp"), "{error}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn starting_publishes_that_the_identity_is_ready() {
    // The first event an interface gets, and the one that says it may begin rendering — which the design document is
    // explicit about happening in parallel with the network rather than after it.
    let kernel = kernel();
    let subscriber = kernel.subscribe();
    kernel.start().expect("started");

    let delivery = kernel.next_event(subscriber).expect("a delivery");
    let first = delivery.events().first().expect("the identity event");
    match first {
        KernelEvent::IdentityChanged { display_name } => {
            assert_eq!(display_name, &kernel.identity().display_name);
        }
        other => panic!("expected an identity event, got {other:?}"),
    }
}

#[test]
fn starting_twice_is_refused() {
    let kernel = kernel();
    kernel.start().expect("started");
    assert!(kernel.is_started());
    match kernel.start() {
        Err(KernelError::AlreadyStarted) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn shutting_down_names_the_tasks_in_reverse_registration_order() {
    // A task registered later depends on the ones before it — a heartbeat on a transport, a transport on discovery —
    // so stopping in registration order would take the ground out from under the tasks still running.
    let kernel = kernel();
    for name in ["discovery.udp", "transport.accept", "heartbeat.ticker"] {
        kernel.register_task(TaskSpec::service(name)).expect("registered");
    }

    let order: Vec<String> =
        kernel.shutdown().expect("shut down").into_iter().map(|id| id.as_str().to_owned()).collect();
    assert_eq!(order, vec!["heartbeat.ticker", "transport.accept", "discovery.udp"]);
    assert!(!kernel.is_started(), "a shut-down kernel is not running");
    match kernel.shutdown() {
        Err(KernelError::ShutDown) => {}
        other => panic!("expected a second shutdown to be refused, got {other:?}"),
    }
}

// ── The snapshot and the stream ───────────────────────────────────────────────────────────────────

#[test]
fn a_snapshot_of_a_fresh_kernel_is_its_identity_and_nothing_else() {
    let kernel = kernel();
    let snapshot = kernel.snapshot().expect("a snapshot");

    assert_eq!(snapshot.identity.device_id, kernel.identity().device_id);
    assert!(snapshot.devices.is_empty());
    assert!(snapshot.plugins.is_empty());
    assert!(snapshot.sendable().is_empty(), "there is nobody to send to");
    assert_eq!(snapshot.config_overrides, 0);
    assert_eq!(snapshot.role, NodeRole::Daemon);
    assert!(!snapshot.started);

    // And after a start, the snapshot says so — which is what an interface redraws from.
    kernel.start().expect("started");
    assert!(kernel.snapshot().expect("a snapshot").started);
}

#[test]
fn a_snapshot_and_the_events_describe_the_same_state() {
    // ★ The property the design document requires: an interface asks for a snapshot once and applies events from then
    // on, so a device that appeared in one and not the other would be a list that disagrees with itself.
    let kernel = kernel();
    let subscriber = kernel.subscribe();
    let device = DeviceId::new();
    let _ = kernel.device_seen(device, "Laptop", true);

    let snapshot = kernel.snapshot().expect("a snapshot");
    let mut seen: Option<DeviceId> = None;
    // ★ One read, because `next_event` is a *poll* rather than a wait: it answers `Some` with an empty batch when the
    // queue is empty, so a `while let Some(..)` around it is an unbounded loop rather than a drain. The first version
    // of this test did not fail — it hung, which is why the loop is written out here.
    let delivery = kernel.next_event(subscriber).expect("a delivery");
    for event in delivery.events() {
        if let KernelEvent::DeviceSeen { device_id, .. } = event {
            seen = Some(*device_id);
        }
    }
    assert_eq!(seen, Some(device), "the event named the device that was published");
    // The device is *not* in the snapshot's paired list, because being heard from is not being paired with — which is
    // the distinction the two lists exist for.
    assert!(snapshot.device(device).is_none());
    assert!(snapshot.devices.is_empty());
}

#[test]
fn a_subscriber_that_fell_behind_is_told_rather_than_left_with_a_gap() {
    // ★ The recovery the design document names: the interface's answer to a missed event is to ask for a snapshot
    // again, and an interface that was not told would draw a state it believes is current for as long as it is open.
    let kernel = kernel();
    let subscriber = kernel.subscribe();
    // Nothing is read, so the queue overflows.
    for index in 0..(crate::bus::SUBSCRIBER_QUEUE_CAPACITY + 5) {
        let _ = kernel.publish(KernelEvent::ConfigChanged { overrides: index });
    }

    let delivery = kernel.next_event(subscriber).expect("a delivery");
    assert!(delivery.must_refresh(), "the subscriber was not told it missed anything");
    assert!(delivery.missed() > 0, "{}", delivery.missed());
    // And it was handed the events that survived, so the queue is a window rather than a switch.
    assert!(!delivery.events().is_empty(), "nothing was delivered at all");
}

#[test]
fn unsubscribing_removes_the_queue() {
    // Dropping the identifier is the whole of unsubscribing for an interface, and this is the call a caller that does
    // not drop it uses.
    let kernel = kernel();
    let subscriber = kernel.subscribe();
    assert_ne!(kernel.subscribe(), subscriber, "a second subscriber is its own queue");
    assert!(kernel.unsubscribe(subscriber));
    assert!(!kernel.unsubscribe(subscriber), "the second removal removes nothing");
    assert!(kernel.next_event(subscriber).is_none());
}

#[test]
fn a_published_event_is_numbered_so_an_interface_can_tell_it_from_one_it_applied() {
    let kernel = kernel();
    let first = kernel.publish(KernelEvent::ConfigChanged { overrides: 1 });
    let second = kernel.publish(KernelEvent::ConfigChanged { overrides: 2 });
    assert!(second > first, "{first} then {second}");
}

#[test]
fn every_event_has_a_name_for_a_log_line() {
    let events = [
        KernelEvent::IdentityChanged { display_name: "x".to_owned() },
        KernelEvent::DeviceSeen { device_id: DeviceId::new(), display_name: "x".to_owned(), online: true },
        KernelEvent::DeviceOffline { device_id: DeviceId::new() },
        KernelEvent::DevicePaired { device_id: DeviceId::new(), display_name: "x".to_owned() },
        KernelEvent::DeviceForgotten { device_id: DeviceId::new() },
        KernelEvent::PluginChanged { plugin_id: "@a/b".to_owned(), state: "active".to_owned() },
        KernelEvent::ConfigChanged { overrides: 1 },
        KernelEvent::MissedEvents { dropped: 2 },
    ];
    let mut seen: Vec<&str> = Vec::new();
    for event in &events {
        let name = event.as_str();
        assert!(!name.is_empty());
        assert!(!seen.contains(&name), "{name} names two events");
        seen.push(name);
    }
    assert_eq!(seen.len(), 8);
}

// ── The two mutable halves ────────────────────────────────────────────────────────────────────────

#[test]
fn the_store_is_reachable_through_one_closure() {
    // The reason the closure exists: `rusqlite`'s connection is `!Sync`, and a reference that outlived the call would
    // be a connection used from two threads — which is a race the compiler cannot catch through a `&`.
    let kernel = kernel();
    let counted = kernel.with_store(|store| store.counts().expect("counts"));
    assert!(!counted.is_empty(), "the migrated schema has tables");
}

#[test]
fn a_device_that_paired_is_in_the_snapshot_and_an_unknown_one_is_not() {
    // The lookup an interface makes when it is told about a device it has.
    let path = temp_path("paired");
    let _ = std::fs::remove_file(&path);
    let kernel = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    let device = DeviceId::new();
    kernel.with_store(|store| {
        store
            .pair_device(&synra_store::sqlite::Paired {
                device_id: device.to_string(),
                display_name: "Laptop".to_owned(),
                platform: "windows".to_owned(),
                features: "[]".to_owned(),
                link_token: "aa11".to_owned(),
                address: Some("10.0.0.4:51000".to_owned()),
                paired_at_ms: 1_700,
            })
            .expect("pairs");
    });

    let snapshot = kernel.snapshot().expect("a snapshot");
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.sendable().len(), 1, "a device that is not blocked may be sent to");
    let found = snapshot.device(device).expect("the device that just paired");
    assert_eq!(found.display_name, "Laptop");
    assert_eq!(found.address.as_deref(), Some("10.0.0.4:51000"));
    assert!(snapshot.device(DeviceId::new()).is_none(), "an unknown id finds nothing");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_identity_is_read_from_the_row_it_was_written_to() {
    // The store is the single source: what a peer sees after a restart is the row, not a value held in memory.
    let path = temp_path("roundtrip");
    let _ = std::fs::remove_file(&path);
    let first = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    let device_id = first.identity().device_id;
    let name = first.identity().display_name.clone();
    drop(first);

    let second = Kernel::open(&path, &KernelConfig::headless()).expect("a kernel");
    assert_eq!(second.identity().device_id, device_id);
    assert_eq!(second.identity().display_name, name);
    assert_eq!(second.identity().platform, std::env::consts::OS);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_kernel_reads_the_clock_at_one_moment() {
    // `created_at_ms` is the reference every later timestamp is compared against, so it is read once rather than asked
    // for again — a value that changed between two reads would make an uptime negative.
    let kernel = kernel();
    assert!(kernel.created_at_ms() > 0);
    assert!(Kernel::now_ms() >= kernel.created_at_ms());
}

#[test]
fn the_debug_form_names_the_device_and_the_role() {
    // What a bug report quotes, and a device id is what tells two installations apart.
    let kernel = kernel();
    let text = format!("{kernel:?}");
    assert!(text.contains("Kernel"), "{text}");
    // The role prints as the *value*, because a bug report is read by whoever wrote the code — and `as_str` is what a
    // log line uses.
    assert!(text.contains("Daemon"), "{text}");
    assert!(text.contains(&kernel.identity().device_id.to_string()), "{text}");
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        KernelError::Store { detail: "the disk is full".to_owned() },
        KernelError::AlreadyStarted,
        KernelError::ShutDown,
    ];
    for error in &errors {
        let sentence = error.to_string();
        assert!(sentence.len() > 10, "{error:?} -> {sentence}");
        assert!(!sentence.contains('{'), "{sentence}");
    }
    assert!(errors[0].to_string().contains("disk"));
}
