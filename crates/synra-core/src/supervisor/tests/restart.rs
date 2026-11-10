use std::time::Duration;
use super::super::{Decision, RestartPolicy, StopReason, TaskSpec, WhyNot};
use super::{NOW, id, supervisor};

#[test]
fn a_service_restarts_with_a_growing_wait() {
    // The shape the policy promises: the first wait is short, and later ones grow to the ceiling rather than
    // without bound.
    let supervisor = supervisor();
    let task = id("transport.accept");
    supervisor
        .register(
            TaskSpec::service(task.clone()).with_policy(RestartPolicy::Backoff {
                max_attempts: 6,
                initial: Duration::from_millis(250),
                max: Duration::from_secs(4),
            }),
        )
        .expect("registered");

    let mut previous = Duration::ZERO;
    let mut grew = 0_u32;
    for attempt in 1..=6 {
        let _ = supervisor.start(&task);
        let decision = supervisor
            .decide(
                &task,
                &StopReason::Failed {
                    detail: format!("attempt {attempt}"),
                },
                NOW,
            )
            .expect("decided");
        let Decision::Restart {
            after,
            attempt: counted,
        } = decision
        else {
            panic!("attempt {attempt} was not restarted: {decision:?}");
        };
        assert_eq!(counted, attempt, "the supervisor counts its own restarts");
        assert!(after > Duration::ZERO, "a wait of zero is a busy loop");
        // ★ The wait never shrinks, and it does grow until it reaches the ceiling. Both halves matter: a
        // symmetric jitter would make the first false, and a schedule that was flat from the start would make
        // the second false while still satisfying the first.
        assert!(
            after >= previous,
            "the wait shrank: {previous:?} -> {after:?}"
        );
        if after > previous {
            grew += 1;
        }
        previous = after;
    }
    assert!(
        grew >= 3,
        "the wait barely grew: {grew} increases over six attempts"
    );
    assert!(
        previous <= Duration::from_secs(4),
        "the wait grew past its ceiling: {previous:?}"
    );
}

#[test]
fn a_once_task_is_never_restarted() {
    let supervisor = supervisor();
    let task = id("bootstrap.open-store");
    supervisor
        .register(TaskSpec::bootstrap(task.clone()))
        .expect("registered");
    let _ = supervisor.start(&task);

    let decision = supervisor
        .decide(
            &task,
            &StopReason::Failed {
                detail: "the disk is full".to_owned(),
            },
            NOW,
        )
        .expect("decided");
    assert_eq!(
        decision,
        Decision::Leave {
            why: WhyNot::RunsOnce
        }
    );
}

#[test]
fn a_plain_retry_policy_does_not_wait() {
    // A caller that wanted a wait asked for `Backoff`. A `Retry` that waited anyway would be a policy whose name
    // does not describe it.
    let supervisor = supervisor();
    let task = id("plugin.activate");
    supervisor
        .register(
            TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 2 }),
        )
        .expect("registered");
    let _ = supervisor.start(&task);

    let decision = supervisor
        .decide(
            &task,
            &StopReason::Failed {
                detail: "it trapped".to_owned(),
            },
            NOW,
        )
        .expect("decided");
    assert_eq!(
        decision,
        Decision::Restart {
            after: Duration::ZERO,
            attempt: 1
        }
    );
}

#[test]
fn a_task_that_keeps_failing_is_given_up_on_with_a_reason() {
    let supervisor = supervisor();
    let task = id("discovery.udp");
    supervisor
        .register(
            TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 3 }),
        )
        .expect("registered");

    for attempt in 1..=3 {
        let _ = supervisor.start(&task);
        let decision = supervisor
            .decide(
                &task,
                &StopReason::Failed {
                    detail: "the port is taken".to_owned(),
                },
                NOW,
            )
            .expect("decided");
        assert!(decision.is_restart(), "attempt {attempt} should restart");
    }
    let _ = supervisor.start(&task);
    let decision = supervisor
        .decide(
            &task,
            &StopReason::Failed {
                detail: "the port is taken".to_owned(),
            },
            NOW,
        )
        .expect("decided");
    match decision {
        Decision::Leave {
            why: WhyNot::AttemptsExhausted { attempts },
        } => assert_eq!(attempts, 3),
        other => panic!("expected the attempts to run out, got {other:?}"),
    }

    let record = supervisor.record(&task).expect("a record");
    assert_eq!(
        record.is_abandoned(),
        Some(WhyNot::AttemptsExhausted { attempts: 3 })
    );
    assert!(
        record.describe().contains("the port is taken"),
        "{}",
        record.describe()
    );
}

#[test]
fn giving_up_is_not_permanent_because_starting_again_is_deliberate() {
    // ★ "The network is down" must become a device that stops trying and *says so*, rather than one that spends
    // an hour of battery. Coming back is a decision somebody makes: the user, a plugin being enabled, a network
    // change — and each of those calls `start`.
    let supervisor = supervisor();
    let task = id("transport.accept");
    supervisor
        .register(
            TaskSpec::service(task.clone()).with_policy(RestartPolicy::Retry { max_attempts: 1 }),
        )
        .expect("registered");
    let _ = supervisor.start(&task);
    let _ = supervisor.decide(
        &task,
        &StopReason::Failed {
            detail: "down".to_owned(),
        },
        NOW,
    );
    let _ = supervisor.start(&task);
    let _ = supervisor.decide(
        &task,
        &StopReason::Failed {
            detail: "still down".to_owned(),
        },
        NOW,
    );
    assert!(supervisor
        .record(&task)
        .expect("a record")
        .is_abandoned()
        .is_some());

    // Starting it again works, and running again is what makes the record healthy.
    supervisor.start(&task).expect("started again");
    assert!(supervisor.record(&task).expect("a record").is_running());
    assert_eq!(supervisor.running_count(), 1);
}

#[test]
fn a_jittered_delay_is_never_zero_and_never_far_from_its_nominal() {
    // A delay that rounded to zero would turn the failure path into a busy loop; one far from its nominal would
    // make the policy's numbers a description of nothing.
    for name in [
        "discovery.udp",
        "transport.accept",
        "heartbeat.ticker",
        "",
        "x",
    ] {
        let task = id(name);
        for attempt in 1..=10 {
            let delay = RestartPolicy::service().delay_for(attempt, &task);
            assert!(
                delay >= Duration::from_millis(1),
                "{name} attempt {attempt}: {delay:?}"
            );
            assert!(
                delay <= Duration::from_secs(30),
                "{name} attempt {attempt}: {delay:?}"
            );
        }
    }
}

#[test]
fn two_tasks_that_failed_together_do_not_come_back_together() {
    // The jitter's whole purpose: a machine whose network went down takes every listener with it, and they must
    // not all retry at the same instant.
    let first = RestartPolicy::service().delay_for(3, &id("discovery.udp"));
    let second = RestartPolicy::service().delay_for(3, &id("discovery.mdns"));
    assert_ne!(first, second, "two tasks got the same delay");
}

#[test]
fn every_policy_and_reason_names_itself() {
    for policy in [
        RestartPolicy::Once,
        RestartPolicy::Retry { max_attempts: 1 },
        RestartPolicy::service(),
    ] {
        assert!(!policy.as_str().is_empty());
        assert!(!policy.as_str().contains(' '));
    }
    for reason in [
        StopReason::Finished,
        StopReason::Cancelled,
        StopReason::Failed {
            detail: "x".to_owned(),
        },
    ] {
        assert!(!reason.as_str().is_empty());
    }
    for why in [
        WhyNot::NotAFailure,
        WhyNot::RunsOnce,
        WhyNot::AttemptsExhausted { attempts: 2 },
        WhyNot::ShuttingDown,
    ] {
        let sentence = why.to_string();
        assert!(sentence.len() > 5, "{why:?} -> {sentence}");
    }
}
