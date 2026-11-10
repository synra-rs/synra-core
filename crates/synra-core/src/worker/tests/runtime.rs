use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use crate::discovery::Absorbed;
use crate::supervisor::Cancellation;
use super::super::run_recording;
use super::{A, B, announcement, device, host, service};

#[test]
fn the_worker_returns_when_it_is_cancelled() {
    // ★ The loop stops when it is cancelled, which its own doc said it could not do.
    //
    // It read: "there is no stop flag ... the thread's work is *inbound*, so ending it early would only be to save a
    // thread on a process that is exiting anyway". That was true of a worker run by a bare `std::thread::spawn` on a
    // process that was going away. Under `supervisor::run_task` the worker is *given* a token and is required to honour
    // it — and a closure that ignores one leaves a thread running after the supervisor has recorded the task as
    // stopped, which is a shutdown report that lies about what is still running.
    //
    // The only wait is the loop's own poll interval, so this is about the token rather than about a timeout.
    let service = Arc::new(Mutex::new(service(A, Duration::from_secs(30))));
    let peers = Arc::new(Mutex::new(host(A, "Laptop")));
    let deadline = Arc::new(AtomicI64::new(0));
    let cancel = Cancellation::new();

    let worker = std::thread::spawn({
        let cancel = cancel.clone();
        move || run_recording(&service, &peers, &deadline, &cancel, || 0, |_| {})
    });

    cancel.cancel();

    assert!(
        worker.join().is_ok(),
        "the worker returned rather than looping for ever"
    );
}

#[test]
fn two_services_find_each_other_over_loopback() {
    // ★ The end-to-end test: two services, each with its own two sockets, and a query that one sends to the other's
    // responder. What is asserted is the round trip a real network does — a query arrives, a candidate is recorded,
    // and the answer carries the announcement back.
    let mut asker = service(A, Duration::from_secs(60));
    let mut answerer = service(B, Duration::from_secs(60));
    let answerer_responder = answerer.responder_address().expect("an address");
    let asker_querier = asker.querier_address().expect("an address");

    let mut asking = host(A, "Laptop");
    // The asker asks the answerer's responder from its own querier, which is what a real scan does.
    asker
        .querier
        .send_query(&announcement(A, "Laptop", 47_100), answerer_responder)
        .expect("asks");

    // The answerer hears the query and answers it.
    let mut answering = host(B, "Phone");
    let ticked = answerer.tick(&mut answering, 5_000, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(A)
        }]
    );

    // ★ The answer goes to the querier, not to the responder — which is the whole reason there are two sockets.
    answerer.answer(asker_querier).expect("answers");

    // And the asker learns about the answerer.
    let ticked = asker.tick(&mut asking, 5_001, Instant::now(), 0);
    assert_eq!(
        ticked.absorbed,
        vec![Absorbed::New {
            device_id: device(B)
        }]
    );
    assert!(asking.discovery().get(device(B)).is_some());
}
