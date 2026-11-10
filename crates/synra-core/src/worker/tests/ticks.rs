use std::time::{Duration, Instant};
use super::{A, host, service};

#[test]
fn the_first_tick_broadcasts_because_a_kernel_that_just_started_has_nothing() {
    // ★ Due immediately rather than after an interval: a kernel that has just started has an empty table, and waiting
    // twenty seconds to ask is twenty seconds of being invisible.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    let ticked = service.tick(&mut kernel, 1_000, Instant::now(), 0);
    assert!(ticked.broadcast);
}

#[test]
fn a_second_tick_before_the_interval_does_not_broadcast() {
    // A broadcast every tick would be a broadcast ten times a second, which is a machine that floods its own network.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    let start = Instant::now();
    assert!(service.tick(&mut kernel, 1_000, start, 0).broadcast);
    assert!(
        !service
            .tick(&mut kernel, 1_001, start + Duration::from_millis(50), 0)
            .broadcast
    );
    assert!(
        service
            .tick(&mut kernel, 1_002, start + Duration::from_secs(61), 0)
            .broadcast
    );
}

#[test]
fn an_idle_tick_reports_no_trouble() {
    // The ordinary case: two sockets with nothing waiting, and a broadcast that may or may not be due. A tick that
    // reported an error here would make every quiet moment look like a fault.
    let mut service = service(A, Duration::from_secs(60));
    let mut kernel = host(A, "Laptop");
    let ticked = service.tick(&mut kernel, 1_000, Instant::now(), 0);
    assert!(ticked.absorbed.is_empty());
    assert!(ticked.askers.is_empty());
    assert!(ticked.errors.is_empty(), "{:?}", ticked.errors);
}
