use std::thread;
use std::time::Duration;
use super::super::{RestartPolicy, StopReason, SupervisorError, TaskSpec, run_task};
use super::{id, supervisor};

#[test]
fn a_running_task_is_started_on_its_own_thread_and_recorded_when_it_returns() {
    // The whole point of the module, driven end to end: a task runs, stops, and the decision is made from what it
    // returned rather than from anywhere else.
    let supervisor = supervisor();
    let task = id("work.once");
    supervisor
        .register(
            TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 1 }),
        )
        .expect("registered");

    let handle = run_task(&supervisor, &task, |_token| {
        Err("the disk is full".to_owned())
    })
    .expect("a thread");
    handle.join().expect("the task finished");

    let record = supervisor.record(&task).expect("a record");
    assert!(!record.is_running());
    assert_eq!(
        record.last_reason,
        Some(StopReason::Failed {
            detail: "the disk is full".to_owned()
        })
    );
}

#[test]
fn a_task_that_stops_because_it_was_cancelled_says_so() {
    // The distinction a supervisor needs: a task that returned cleanly because it was asked to is not a task that
    // finished its work, and restarting it would undo a decision.
    let supervisor = supervisor();
    let task = id("work.forever");
    supervisor
        .register(TaskSpec::service(task.clone()))
        .expect("registered");

    let token = supervisor.cancellation();
    let handle = run_task(&supervisor, &task, move |given| {
        let _ = given.wait(Duration::from_secs(1));
        Ok(())
    })
    .expect("a thread");
    thread::sleep(Duration::from_millis(20));
    token.cancel();
    handle.join().expect("the task finished");

    assert_eq!(
        supervisor.record(&task).expect("a record").last_reason,
        Some(StopReason::Cancelled)
    );
}

#[test]
fn running_a_task_nothing_registered_is_refused_before_a_thread_starts() {
    let supervisor = supervisor();
    match run_task(&supervisor, &id("ghost"), |_token| Ok(())) {
        Err(SupervisorError::Unknown { id: name }) => assert_eq!(name.as_str(), "ghost"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
