use std::time::{Duration, Instant};
use crate::discovery::Absorbed;
use crate::test_support::{announcement, device, host};
use super::{A, B, loopback};

#[test]
fn a_scan_stops_at_its_deadline_and_returns_what_it_heard() {
    // The budget is what keeps "scanning" from being forever in the interface.
    let socket = loopback();
    let mut kernel = host(A, "Laptop");
    let started = Instant::now();
    let results = socket.scan_until(&mut kernel, 5_000, started + Duration::from_millis(120));
    assert!(
        results.is_empty(),
        "something answered a loopback port nothing is sending to"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(100),
        "the scan returned early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the scan overran its budget: {elapsed:?}"
    );
}

#[test]
fn a_scan_collects_a_query_that_arrives_while_it_runs() {
    // The realistic case: a scan is a wait, and a device that answers during the wait is found.
    let receiver = loopback();
    let target = receiver.local_addr().expect("an address");
    let sender = loopback();

    let sending = std::thread::spawn(move || {
        // Long enough for the scan to have started waiting, short enough to be inside its budget.
        std::thread::sleep(Duration::from_millis(40));
        sender
            .send_query(&announcement(B, "Phone", 47101), target)
            .expect("sends");
    });

    let mut kernel = host(A, "Laptop");
    let results = receiver.scan_until(
        &mut kernel,
        5_000,
        Instant::now() + Duration::from_millis(400),
    );
    sending.join().expect("finished");

    assert_eq!(
        results,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    assert!(kernel.discovery().get(device(B)).is_some());
}
