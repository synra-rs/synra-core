use super::*;

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
