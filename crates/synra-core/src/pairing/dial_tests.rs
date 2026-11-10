use super::*;
use std::time::Duration;

#[test]
fn the_initiator_wakes_with_its_own_cancellation() {
    let service = Service::new();
    let peer = DeviceId::new();
    service
        .begin(peer, "Pixel", PlatformKind::Android, false)
        .expect("an empty desk");

    let waiter_service = std::sync::Arc::clone(&service);
    let waiter =
        std::thread::spawn(move || waiter_service.wait_for_decision(Duration::from_secs(5)));

    std::thread::sleep(Duration::from_millis(20));
    assert!(service.cancel().is_ok());

    assert_eq!(waiter.join().expect("the waiter"), Decision::Cancelled);
}

#[test]
fn the_initiator_wakes_when_the_peer_accepts() {
    let service = Service::new();
    let peer = DeviceId::new();
    service
        .begin(peer, "Pixel", PlatformKind::Android, false)
        .expect("an empty desk");

    let waiter_service = std::sync::Arc::clone(&service);
    let waiter =
        std::thread::spawn(move || waiter_service.wait_for_decision(Duration::from_secs(5)));

    std::thread::sleep(Duration::from_millis(20));
    assert!(service.answered(true).is_ok());

    assert_eq!(waiter.join().expect("the waiter"), Decision::Accepted);
}

#[test]
fn the_initiator_wakes_when_the_peer_refuses() {
    let service = Service::new();
    let peer = DeviceId::new();
    service
        .begin(peer, "Pixel", PlatformKind::Android, false)
        .expect("an empty desk");

    let waiter_service = std::sync::Arc::clone(&service);
    let waiter =
        std::thread::spawn(move || waiter_service.wait_for_decision(Duration::from_secs(5)));

    std::thread::sleep(Duration::from_millis(20));
    assert!(service.answered(false).is_ok());

    assert_eq!(waiter.join().expect("the waiter"), Decision::Refused);
}
