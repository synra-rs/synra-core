use std::thread;
use std::time::Duration;
use super::super::Cancellation;
use super::supervisor;

#[test]
fn a_cancellation_is_visible_to_everyone_holding_a_clone() {
    let supervisor = supervisor();
    let token = supervisor.cancellation();
    assert!(!token.is_cancelled());
    let _ = supervisor.begin_shutdown();
    assert!(
        token.is_cancelled(),
        "a clone is the same token, not a copy of it"
    );
}

#[test]
fn waiting_on_a_cancellation_returns_when_it_is_cancelled() {
    let token = Cancellation::new();
    let waiter = token.clone();
    let handle = thread::spawn(move || waiter.wait(Duration::from_secs(2)));
    thread::sleep(Duration::from_millis(20));
    token.cancel();

    assert!(
        handle.join().expect("the waiter"),
        "the wait did not notice the cancellation"
    );
}

#[test]
fn waiting_on_a_cancellation_that_never_comes_times_out() {
    // A shutdown that waits for ever is a window that will not close, so the wait has to be bounded even when
    // the answer is no.
    let token = Cancellation::new();
    assert!(!token.wait(Duration::from_millis(30)));
}
