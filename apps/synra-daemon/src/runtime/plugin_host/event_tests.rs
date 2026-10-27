//! Production daemon host, actual WIT guest code, asynchronous worker and real file SQLite.

use super::*;
use std::time::{Duration, Instant};
use synra_core::dispatch::{PluginSet, PluginSpec};
use synra_plugin_host::{
    Backend, BackendKind, CallBudget, CallOutcome, InstancePolicy, Work, quota::Quota,
};
use synra_protocol::{ErrorCode, TraceId};
use synra_testkit::plugin_events::{DEVICE, EVENT, EventPlugin};

struct Rig {
    db: Arc<Mutex<synra_store::SynraDb>>,
    set: Arc<Mutex<PluginSet>>,
    service: Arc<synra_core::plugin_events::EventService>,
    emitter: EventPlugin,
    receiver: EventPlugin,
    // Dropped after the set, service and SQLite handles.
    _root: EventDirectory,
}

struct EventDirectory {
    directory: Option<tempfile::TempDir>,
    service: std::sync::Weak<synra_core::plugin_events::EventService>,
}

impl Drop for EventDirectory {
    fn drop(&mut self) {
        // A finished handler may still be returning from the worker's stack. Wait for its
        // actual Arc to drop before closing a Windows SQLite file's directory.
        wait(|| self.service.strong_count() == 0);
        self.directory.take().unwrap().close().unwrap();
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.service.stop();
        wait(|| !self.service.report().worker_running);
    }
}

impl Rig {
    fn new(looping: bool, condition: Option<serde_json::Value>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut db = synra_store::SynraDb::open(&root.path().join("events.sqlite3")).unwrap();
        db.migrate().unwrap();
        let mut emitter = EventPlugin::emitter(looping).unwrap();
        let receiver = EventPlugin::receiver(condition).unwrap();
        // Deliberately allow payload fields named like context fields; they must stay nested.
        let mut manifest: serde_json::Value = serde_json::from_str(&emitter.manifest).unwrap();
        manifest["events"][0]["payload"]["additionalProperties"] = serde_json::Value::Bool(true);
        emitter.manifest = manifest.to_string();
        emitter.persist(&db).unwrap();
        receiver.persist(&db).unwrap();
        let db = Arc::new(Mutex::new(db));
        let host = Arc::new(KernelHost::new(Arc::clone(&db), "test"));
        let service = host.events();
        let engine =
            synra_plugin_host::engine::WasmtimeBackend::new(BackendKind::WasmtimeCranelift)
                .unwrap();
        let set = PluginSet::new(Backend::new(Arc::new(engine)), host)
            .with_event_delivery(Arc::clone(&service))
            .into_shared()
            .unwrap();
        {
            let mut set = set.lock();
            load(&mut set, &emitter);
            if !looping {
                load(&mut set, &receiver);
            }
        }
        Self {
            _root: EventDirectory {
                directory: Some(root),
                service: Arc::downgrade(&service),
            },
            db,
            set,
            service,
            emitter,
            receiver,
        }
    }

    fn emit(&self, payload: serde_json::Value, trace: TraceId) -> CallOutcome {
        self.set
            .lock()
            .call_traced(
                &self.emitter.id,
                &Work::InvokeAction {
                    name: "emit".to_owned(),
                    args_json: payload.to_string(),
                },
                CallBudget::from_quota(&Quota::default()),
                1,
                Some(trace),
            )
            .unwrap()
    }

    fn stored(&self, key: &str) -> Option<String> {
        self.db
            .lock()
            .storage_get(self.receiver.id.as_str(), key)
            .unwrap()
    }
}

fn load(set: &mut PluginSet, plugin: &EventPlugin) {
    set.load_with_lifecycle(
        PluginSpec {
            id: plugin.id.clone(),
            version: "1.0.0".to_owned(),
            wasm: plugin.wasm.clone(),
            grants: synra_capability::CapabilitySet::parse_all(
                plugin.grants.iter().map(String::as_str),
            )
            .unwrap(),
            policy: InstancePolicy::Stateful,
            limit: 1,
            quota: Quota {
                events_per_sec: 1_000,
                ..Quota::default()
            },
        },
        synra_plugin_api::manifest_digest(&plugin.manifest),
        false,
    )
    .unwrap();
    assert!(matches!(
        set.call(
            &plugin.id,
            &Work::Activate {
                config_json: "{}".to_owned()
            },
            CallBudget::from_quota(&Quota::default()),
            1
        )
        .unwrap(),
        CallOutcome::Ok(_)
    ));
    set.mark_active(&plugin.id).unwrap();
}

fn wait(mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if ready() {
            return;
        }
        assert!(
            Instant::now() < until,
            "event worker did not reach the expected state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn callers_outside_a_guest_execution_cannot_spoof_event_emission() {
    let rig = Rig::new(false, None);
    let host = KernelHost::new(Arc::clone(&rig.db), "test");
    let error = host.event_emit(&rig.emitter.id, EVENT, "{}").unwrap_err();
    assert_eq!(error.code, ErrorCode::CapabilityDenied.as_str());
    assert_eq!(rig.service.report().pending, 0);
}

#[test]
fn actual_guest_emission_reaches_a_different_guest_and_keeps_host_context_and_trace() {
    let rig = Rig::new(false, None);
    let trace = TraceId::new();
    let payload = serde_json::json!({"text":"中文🖱️","from":"spoofed","traceId":"fake","senderPluginId":"@other/emitter"});
    assert!(matches!(
        rig.emit(payload.clone(), trace),
        CallOutcome::Ok(_)
    ));
    wait(|| rig.service.report().delivered == 1);
    let context: serde_json::Value =
        serde_json::from_str(&rig.stored("received").unwrap()).unwrap();
    assert_eq!(context["payload"], payload);
    assert_eq!(context["from"], DEVICE);
    assert_eq!(context["senderPluginId"], "@acme/emitter");
    assert_eq!(context["event"], EVENT);
    assert_eq!(context["traceId"], serde_json::to_value(trace).unwrap());
    assert_eq!(rig.stored("calls").as_deref(), Some("1"));
    let audit = rig.set.lock().audit_for(&rig.receiver.id);
    assert_eq!(audit.len(), 2);
    assert!(audit.iter().all(|entry| entry.trace == Some(trace)));
}

#[test]
fn payload_validation_happens_before_queue_admission_without_echoing_values() {
    let rig = Rig::new(false, None);
    for payload in [
        serde_json::json!({}),
        serde_json::json!({"text":123}),
        serde_json::json!({"text":"private selection that is far too long to fit this event schema"}),
    ] {
        let outcome = rig.emit(payload, TraceId::new());
        let CallOutcome::Failed { code, message, .. } = outcome else {
            panic!("schema-invalid event was admitted")
        };
        assert_eq!(code, "invalid_argument");
        assert!(!message.contains("private selection"));
    }
    assert_eq!(rig.service.report().pending, 0);
    assert_eq!(rig.service.report().delivered, 0);
    assert!(rig.stored("received").is_none());
}

#[test]
fn queued_work_rechecks_persisted_receive_and_emit_authority() {
    for revoke_source in [false, true] {
        let rig = Rig::new(false, None);
        let mut set = rig.set.lock();
        assert!(matches!(
            set.call_traced(
                &rig.emitter.id,
                &Work::InvokeAction {
                    name: "emit".to_owned(),
                    args_json: r#"{"text":"held"}"#.to_owned()
                },
                CallBudget::from_quota(&Quota::default()),
                1,
                Some(TraceId::new())
            )
            .unwrap(),
            CallOutcome::Ok(_)
        ));
        let plugin = if revoke_source {
            &rig.emitter
        } else {
            &rig.receiver
        };
        let capability = format!(
            "event:{}:{EVENT}",
            if revoke_source { "emit" } else { "subscribe" }
        );
        rig.db
            .lock()
            .record_grants(
                plugin.id.as_str(),
                &[(capability, false)],
                2,
                &synra_plugin_api::manifest_digest(&plugin.manifest),
            )
            .unwrap();
        drop(set);
        wait(|| rig.service.report().refused > 0);
        assert!(rig.stored("received").is_none());
        assert!(
            rig.service
                .report()
                .recent
                .iter()
                .any(|entry| entry.error == Some(ErrorCode::CapabilityDenied))
        );
    }
}

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
