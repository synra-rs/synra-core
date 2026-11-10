use synra_plugin_host::{CallBudget, CallOutcome, Work, quota::Quota};
use synra_protocol::{ErrorCode, TraceId};

use super::{Rig, load, wait};

#[test]
fn queued_events_cannot_cross_an_unload_and_reload_of_the_same_version() {
    let rig = Rig::new(false, None);
    let stale_trace = TraceId::new();
    let mut set = rig.set.lock();
    assert!(matches!(
        set.call_traced(
            &rig.emitter.id,
            &Work::InvokeAction {
                name: "emit".to_owned(),
                args_json: r#"{"text":"stale"}"#.to_owned()
            },
            CallBudget::from_quota(&Quota::default()),
            1,
            Some(stale_trace)
        )
        .unwrap(),
        CallOutcome::Ok(_)
    ));
    assert!(set.unload(&rig.emitter.id));
    load(&mut set, &rig.emitter);
    drop(set);
    wait(|| rig.service.report().refused > 0);
    assert!(rig.stored("received").is_none());
    assert!(matches!(
        rig.emit(serde_json::json!({"text":"current"}), TraceId::new()),
        CallOutcome::Ok(_)
    ));
    wait(|| rig.service.report().delivered == 1);
    assert_eq!(rig.stored("calls").as_deref(), Some("1"));
    assert!(
        rig.service
            .report()
            .recent
            .iter()
            .any(|entry| entry.trace_id == stale_trace && !entry.delivered)
    );
}

#[test]
fn declared_conditions_filter_payloads_and_event_cycles_hit_a_finite_budget() {
    let rig = Rig::new(false, Some(serde_json::json!({"kind":"allowed"})));
    assert!(matches!(
        rig.emit(
            serde_json::json!({"text":"filtered","kind":"other"}),
            TraceId::new()
        ),
        CallOutcome::Ok(_)
    ));
    wait(|| rig.service.report().unhandled == 1);
    assert!(rig.stored("received").is_none());
    assert!(matches!(
        rig.emit(
            serde_json::json!({"text":"received","kind":"allowed"}),
            TraceId::new()
        ),
        CallOutcome::Ok(_)
    ));
    wait(|| rig.service.report().delivered == 1);
    let looping = Rig::new(true, None);
    let trace = TraceId::new();
    assert!(matches!(
        looping.emit(serde_json::json!({"text":"loop"}), trace),
        CallOutcome::Ok(_)
    ));
    wait(|| looping.service.report().refused > 0);
    let report = looping.service.report();
    assert_eq!(report.pending, 0);
    assert!(report.delivered <= 8);
    assert!(
        report
            .recent
            .iter()
            .any(|entry| entry.error == Some(ErrorCode::RateLimited))
    );
    assert!(report.recent.iter().all(|entry| entry.trace_id == trace));
}

#[test]
fn a_blocked_receiver_cannot_grow_the_event_queue_without_bound() {
    let rig = Rig::new(false, None);
    let mut set = rig.set.lock();
    let mut accepted = 0;
    let mut refused = 0;
    for _ in 0..130 {
        let outcome = set
            .call_traced(
                &rig.emitter.id,
                &Work::InvokeAction {
                    name: "emit".to_owned(),
                    args_json: r#"{"text":"queued"}"#.to_owned(),
                },
                CallBudget::from_quota(&Quota::default()),
                1,
                Some(TraceId::new()),
            )
            .unwrap();
        match outcome {
            CallOutcome::Ok(_) => accepted += 1,
            CallOutcome::Failed { code, message, .. } => {
                assert_eq!(code, "rate_limited");
                assert!(message.contains("queue is full"), "{message}");
                refused += 1;
            }
            outcome => panic!("unexpected event outcome: {outcome:?}"),
        }
    }
    // One worker may have removed an item before blocking on this set's lock.
    assert!((128..=129).contains(&accepted));
    assert_eq!(accepted + refused, 130);
    assert!(rig.service.report().pending <= synra_core::plugin_events::MAX_PENDING);
    rig.service.stop();
    drop(set);
    wait(|| !rig.service.report().worker_running);
    assert_eq!(rig.service.report().pending, 0);
    assert_eq!(rig.service.report().queued_bytes, 0);
    assert_eq!(rig.service.report().delivered, 0);
}
