use super::*;

const NOW: i64 = 1_000;

fn supervisor() -> Arc<Supervisor> {
    Arc::new(Supervisor::new(NOW))
}

fn id(name: &str) -> TaskId {
    TaskId::new(name)
}

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
