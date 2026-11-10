use super::super::{Decision, StopReason, SupervisorError, TaskSpec, WhyNot};
use super::{NOW, id, supervisor};

#[test]
fn a_task_is_registered_and_starts_stopped() {
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("discovery.udp"))
        .expect("registered");

    let record = supervisor.record(&id("discovery.udp")).expect("a record");
    assert!(!record.is_running(), "registering is not starting");
    assert_eq!(record.restarts, 0);
    assert_eq!(supervisor.running_count(), 0);
    assert_eq!(supervisor.len(), 1);
    assert!(!supervisor.is_empty());
    // And nothing critical has failed, so the kernel is healthy with nothing running yet.
    assert!(supervisor.is_healthy());
}

#[test]
fn two_tasks_with_one_name_are_refused() {
    // ★ Two tasks with one name would make every log line about either of them ambiguous, and the second
    // registration is far more likely to be a copy-paste mistake than an intent.
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("transport.accept"))
        .expect("registered");
    match supervisor.register(TaskSpec::service("transport.accept")) {
        Err(SupervisorError::AlreadyRegistered { id: name }) => {
            assert_eq!(name.as_str(), "transport.accept");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn starting_a_task_nothing_registered_is_refused() {
    // The check that matters: a task that started without being registered is one nothing is watching.
    let supervisor = supervisor();
    match supervisor.start(&id("ghost")) {
        Err(SupervisorError::Unknown { id: name }) => assert_eq!(name.as_str(), "ghost"),
        other => panic!("expected an unknown-task refusal, got {other:?}"),
    }
}

#[test]
fn starting_twice_counts_one_running_task() {
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("heartbeat.ticker"))
        .expect("registered");
    supervisor.start(&id("heartbeat.ticker")).expect("started");
    supervisor
        .start(&id("heartbeat.ticker"))
        .expect("started again");

    assert_eq!(
        supervisor.running_count(),
        1,
        "a task started twice is one task"
    );
}

#[test]
fn a_finished_task_is_not_restarted() {
    // ★ Restarting a task that finished would undo a decision somebody made — and a shutdown that restarted its
    // own tasks would never finish.
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("bootstrap.load-store"))
        .expect("registered");
    let _ = supervisor.start(&id("bootstrap.load-store"));

    let decision = supervisor
        .decide(&id("bootstrap.load-store"), &StopReason::Finished, NOW)
        .expect("decided");
    assert_eq!(
        decision,
        Decision::Leave {
            why: WhyNot::NotAFailure
        }
    );
    assert_eq!(supervisor.running_count(), 0);
    assert!(supervisor.stopped().len() == 1);
}

#[test]
fn a_cancelled_task_is_not_restarted_even_by_a_service_policy() {
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("discovery.udp"))
        .expect("registered");
    let _ = supervisor.start(&id("discovery.udp"));

    let decision = supervisor
        .decide(&id("discovery.udp"), &StopReason::Cancelled, NOW)
        .expect("decided");
    assert!(!decision.is_restart());
}

#[test]
fn a_task_id_can_be_searched_by_area() {
    // The convention — `area.thing` — is what makes a prefix search meaningful in a `doctor` report.
    let udp = id("discovery.udp");
    assert!(udp.is_in("discovery."));
    assert!(!udp.is_in("transport."));
    assert!(
        !id("discovery").is_in("discovery."),
        "the area alone is not in the area"
    );
    assert_eq!(udp.to_string(), "discovery.udp");
}
