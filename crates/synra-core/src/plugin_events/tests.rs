use super::*;
use synra_plugin_host::{Backend, ScriptedBackend, testing::RefusingHost};

fn service() -> Arc<EventService> {
    let mut db = synra_store::SynraDb::open_in_memory().unwrap();
    db.migrate().unwrap();
    EventService::new(Arc::new(Mutex::new(db)))
}

fn runtime(service: &Arc<EventService>) -> Arc<Mutex<PluginSet>> {
    PluginSet::new(
        Backend::new(Arc::new(ScriptedBackend::new())),
        Arc::new(RefusingHost),
    )
    .with_event_delivery(Arc::clone(service))
    .into_shared()
    .unwrap()
}

fn pending() -> Pending {
    let runtime = RequestId::new();
    Pending {
        event: EventName::parse("_plugin.@acme/emitter.ready").unwrap(),
        from: DeviceId::new(),
        source: Arc::new(context::Execution {
            runtime,
            generation: RequestId::new(),
            plugin: PluginId::parse("@acme/emitter").unwrap(),
            version: "1.0.0".to_owned(),
            manifest_digest: "fixture".to_owned(),
        }),
        request: RequestId::new(),
        trace: TraceId::new(),
        payload: serde_json::json!({"text":"private"}),
        bytes: 18,
        deadline: Instant::now(),
        cause: context::Cause::root(runtime),
    }
}

#[test]
fn a_service_cannot_rebind_while_its_previous_runtime_is_alive() {
    let service = service();
    let first = runtime(&service);
    let second = PluginSet::new(
        Backend::new(Arc::new(ScriptedBackend::new())),
        Arc::new(RefusingHost),
    )
    .with_event_delivery(Arc::clone(&service))
    .into_shared();
    assert_eq!(second.unwrap_err().code, ErrorCode::Internal);
    drop(first);
    assert!(service.report().stopping);
    let replacement = PluginSet::new(
        Backend::new(Arc::new(ScriptedBackend::new())),
        Arc::new(RefusingHost),
    )
    .with_event_delivery(Arc::clone(&service))
    .into_shared();
    assert!(replacement.is_err());
}

#[test]
fn shutdown_discards_queued_payloads_and_accounts_for_refusals() {
    let service = service();
    {
        let mut state = service.state.lock();
        state.pending.extend([pending(), pending()]);
        state.bytes = 36;
        state.worker_running = true;
    }
    Arc::clone(&service).run();
    let report = service.report();
    assert_eq!(report.pending, 0);
    assert_eq!(report.queued_bytes, 0);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.refused, 2);
    assert!(!service.state.lock().worker_running);
}

#[test]
fn an_already_expired_event_is_refused_before_any_guest_or_policy_read() {
    let service = service();
    let set = runtime(&service);
    {
        let mut state = service.state.lock();
        state.pending.push_back(pending());
        state.bytes = 18;
        state.worker_running = true;
    }
    let worker_service = Arc::clone(&service);
    let thread = std::thread::spawn(move || worker_service.run());
    let deadline = Instant::now() + Duration::from_secs(2);
    while service.report().refused == 0 {
        assert!(Instant::now() < deadline, "expiry worker stalled");
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(set);
    thread.join().unwrap();
    let report = service.report();
    assert_eq!(report.recent.len(), 1);
    assert_eq!(report.recent[0].error, Some(ErrorCode::Timeout));
    assert_eq!(report.pending, 0);
    assert_eq!(report.queued_bytes, 0);
}

#[test]
fn diagnostics_stay_bounded_and_native_metrics_receive_classified_results() {
    let service = service();
    let metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
    service.state.lock().metrics = Some(Arc::clone(&metrics));
    let pending = pending();
    for _ in 0..100 {
        service.record(&pending, None, Some(ErrorCode::Timeout), false);
    }
    service.record(&pending, None, None, true);
    service.record(&pending, None, None, false);
    let report = service.report();
    assert_eq!(
        (report.refused, report.delivered, report.unhandled),
        (100, 1, 1)
    );
    assert_eq!(report.recent.len(), 64);
    assert!(!serde_json::to_string(&report).unwrap().contains("private"));
    let snapshot = metrics.snapshot();
    let key = synra_observe::metrics::SeriesKey::new(
        "plugin_event_deliveries_total",
        [("outcome".to_owned(), "refused".to_owned())],
    );
    assert_eq!(
        snapshot.get(&key.render()),
        Some(&synra_observe::metrics::Value::Counter(100))
    );
}

#[test]
fn causal_limits_are_shared_across_parallel_branches_and_scopes_restore_identity() {
    let pending = pending();
    assert!(context::current().is_none());
    {
        let _scope = context::enter(Arc::clone(&pending.source));
        assert!(Arc::ptr_eq(&context::current().unwrap(), &pending.source));
    }
    assert!(context::current().is_none());
    let cause = context::Cause::root(RequestId::new());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let branch = cause.clone();
            std::thread::spawn(move || (0..32).filter(|_| branch.take_delivery()).count())
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .sum::<usize>(),
        32
    );
    let mut branch = cause.clone();
    for _ in 0..8 {
        branch = branch.next().unwrap();
    }
    assert!(branch.next().is_none());
    for _ in 0..24 {
        assert!(cause.next().is_some());
    }
    assert!(cause.next().is_none());
}
