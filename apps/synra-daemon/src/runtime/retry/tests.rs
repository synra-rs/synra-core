use super::*;
use synra_core::intent::{Choice, IntentSource, IntentState};
use synra_protocol::ids::{PluginId, RequestId};

#[test]
fn a_dispatch_with_no_known_address_is_counted_and_left_alone() {
    // ★ The pass must not invent an address, and must not change the intent when it cannot send: "I could not reach
    // it" is not "it failed", and the 24-hour expiry or a late answer still owns the outcome.
    let dir = std::env::temp_dir().join(format!("synra-daemon-retry-{}", RequestId::new()));
    std::fs::create_dir_all(&dir).expect("a temp dir");
    let runtime = crate::runtime::tests::runtime(&dir);
    let peer = DeviceId::new();
    let now = synra_store::sqlite::now_ms();
    let (id, ..) = runtime.board.lock().raise(
        IntentSource::Direct {
            plugin_id: PluginId::parse("@acme/opener").expect("a plugin id"),
            action: "open".to_owned(),
            params: serde_json::json!({}),
            target: peer,
        },
        Choice::Automatic,
        None,
        Some(RequestId::new()),
        now,
    );

    let report = resend_outstanding(
        &runtime.host,
        &runtime.board,
        &runtime.db,
        runtime.identity.device_id,
    );

    assert_eq!(report.attempted, 1);
    assert_eq!(report.failed, 1, "there is no address to dial");
    assert!(matches!(
        runtime.board.lock().get(id).map(|intent| intent.state.clone()),
        Some(IntentState::Dispatching { .. })
    ));
    drop(runtime);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_retry_loop_stops_when_it_is_cancelled() {
    // ★ The shutdown path: the loop sleeps for up to thirty seconds when nothing is pending, so it has to notice a
    // cancellation inside a slice rather than after the whole wait. A daemon that will not close is worse than one
    // that never retried.
    let dir = std::env::temp_dir().join(format!("synra-daemon-retry-loop-{}", RequestId::new()));
    std::fs::create_dir_all(&dir).expect("a temp dir");
    let runtime = crate::runtime::tests::runtime(&dir);
    let host = Arc::clone(&runtime.host);
    let board = Arc::clone(&runtime.board);
    let db = Arc::clone(&runtime.db);
    let local = runtime.identity.device_id;
    let cancel = Cancellation::new();
    let token = cancel.clone();

    let handle = std::thread::spawn(move || run(&host, &board, &db, local, &token, RetryPolicy::default()));
    std::thread::sleep(Duration::from_millis(30));
    cancel.cancel();
    handle.join().expect("the loop returned after the cancellation");

    drop(runtime);
    let _ = std::fs::remove_dir_all(&dir);
}
