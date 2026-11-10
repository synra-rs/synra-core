use super::*;

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
