use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn a_change_calls_the_sink_the_shell_installed() {
    let service = Service::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    service.set_sink(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    service
        .receive(
            PairCode::new(11).expect("in range"),
            DeviceId::new(),
            "Laptop",
            PlatformKind::Desktop,
            false,
        )
        .expect("an empty desk");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    assert!(service.accept().is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
