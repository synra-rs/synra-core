use super::*;
use std::time::Duration;

#[test]
fn a_waiting_connection_is_woken_by_the_answer() {
    let service = Service::new();
    service
        .receive(
            PairCode::new(7).expect("in range"),
            DeviceId::new(),
            "Laptop",
            PlatformKind::Desktop,
            false,
        )
        .expect("an empty desk");

    let answerer = std::sync::Arc::clone(&service);
    let waiter = std::thread::spawn(move || answerer.wait_for_decision(Duration::from_secs(5)));

    std::thread::sleep(Duration::from_millis(20));
    assert!(service.accept().is_ok());

    assert_eq!(waiter.join().expect("the waiter"), Decision::Accepted);
}

#[test]
fn a_refusal_wakes_the_waiter_with_a_refusal() {
    let service = Service::new();
    service
        .receive(
            PairCode::new(8).expect("in range"),
            DeviceId::new(),
            "Laptop",
            PlatformKind::Desktop,
            false,
        )
        .expect("an empty desk");

    let answerer = std::sync::Arc::clone(&service);
    let waiter = std::thread::spawn(move || answerer.wait_for_decision(Duration::from_secs(5)));

    std::thread::sleep(Duration::from_millis(20));
    assert!(service.refuse().is_ok());

    assert_eq!(waiter.join().expect("the waiter"), Decision::Refused);
}

#[test]
fn nobody_answering_ends_in_a_timeout_rather_than_a_guess() {
    let service = Service::new();
    service
        .receive(
            PairCode::new(9).expect("in range"),
            DeviceId::new(),
            "Laptop",
            PlatformKind::Desktop,
            false,
        )
        .expect("an empty desk");

    assert_eq!(
        service.wait_for_decision(Duration::from_millis(50)),
        Decision::TimedOut
    );
}
