use std::sync::Arc;

use synra_plugin_host::{CallBudget, CallOutcome, Work, host_calls::Host as _, quota::Quota};
use synra_protocol::{ErrorCode, TraceId};
use synra_testkit::plugin_events::{DEVICE, EVENT};

use super::super::KernelHost;
use super::{Rig, wait};

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
