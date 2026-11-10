use super::super::{Decision, StopReason, SupervisorError, TaskSpec, WhyNot};
use super::{NOW, id, supervisor};

#[test]
fn a_shutdown_stops_restarts_whatever_the_policy_says() {
    // ★ A shutdown that restarted a task would never finish: the task would come back, be cancelled again, and
    // come back again.
    let supervisor = supervisor();
    let task = id("discovery.udp");
    supervisor
        .register(TaskSpec::service(task.clone()))
        .expect("registered");
    let _ = supervisor.start(&task);

    let order = supervisor.begin_shutdown();
    assert!(supervisor.is_shutting_down());
    assert_eq!(
        order,
        vec![task.clone()],
        "one task, in reverse registration order"
    );

    let decision = supervisor
        .decide(
            &task,
            &StopReason::Failed {
                detail: "it noticed the shutdown".to_owned(),
            },
            NOW,
        )
        .expect("decided");
    assert_eq!(
        decision,
        Decision::Leave {
            why: WhyNot::ShuttingDown
        }
    );
    assert!(matches!(
        supervisor.register(TaskSpec::service("late")),
        Err(SupervisorError::ShutDown)
    ));
}

#[test]
fn the_shutdown_order_is_the_reverse_of_registration() {
    // A task registered later depends on the ones before it — a heartbeat on a transport, a transport on
    // discovery — so stopping in registration order would take the ground out from under the tasks still running.
    let supervisor = supervisor();
    for name in ["discovery.udp", "transport.accept", "heartbeat.ticker"] {
        supervisor
            .register(TaskSpec::service(name))
            .expect("registered");
    }
    let order: Vec<String> = supervisor
        .begin_shutdown()
        .into_iter()
        .map(|id| id.0)
        .collect();
    assert_eq!(
        order,
        vec!["heartbeat.ticker", "transport.accept", "discovery.udp"]
    );
}

#[test]
fn the_report_says_what_did_not_stop() {
    // A task that did not stop is a fact the caller has to act on: a process that exits with a locked port will
    // not start again.
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("discovery.udp"))
        .expect("registered");
    supervisor
        .register(TaskSpec::service("transport.accept"))
        .expect("registered");
    let _ = supervisor.start(&id("discovery.udp"));
    let _ = supervisor.start(&id("transport.accept"));

    // One stops, the other does not.
    let _ = supervisor
        .decide(&id("transport.accept"), &StopReason::Cancelled, NOW)
        .expect("decided");
    let report = supervisor.report();

    assert!(!report.is_clean());
    assert_eq!(report.stopped, vec![id("transport.accept")]);
    assert_eq!(report.still_running, vec![id("discovery.udp")]);
    assert!(
        report.describe().contains("did not"),
        "{}",
        report.describe()
    );
}

#[test]
fn health_is_about_the_critical_tasks_and_not_about_every_task() {
    // ★ A discovery listener that failed is not a kernel that is broken, and a health report that treated the two
    // the same would be one a user learns to ignore.
    let supervisor = supervisor();
    supervisor
        .register(TaskSpec::service("discovery.udp"))
        .expect("registered");
    supervisor
        .register(TaskSpec::service("transport.accept").critical())
        .expect("registered");
    let _ = supervisor.start(&id("discovery.udp"));
    let _ = supervisor.start(&id("transport.accept"));
    assert!(supervisor.is_healthy());

    // The ordinary one failing leaves the kernel healthy.
    let _ = supervisor.decide(
        &id("discovery.udp"),
        &StopReason::Failed {
            detail: "no network".to_owned(),
        },
        NOW,
    );
    assert!(
        supervisor.is_healthy(),
        "an ordinary task failing is not a broken kernel"
    );

    // The critical one failing does not.
    let _ = supervisor.decide(
        &id("transport.accept"),
        &StopReason::Failed {
            detail: "port taken".to_owned(),
        },
        NOW,
    );
    assert!(!supervisor.is_healthy());
}
