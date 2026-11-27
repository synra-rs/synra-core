//! A real typed WIT log import must enforce the current concrete level grant.

use std::sync::Arc;

use synra_capability::CapabilitySet;
use synra_protocol::ids::PluginId;

use crate::engine::{
    Backend, BackendKind, CallBudget, CallOutcome, LinkerSession, WasmBackend, WasmtimeBackend,
    Work,
};
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;

const COMPONENT: &str = r#"
(module
  (import "synra:plugin/host@1.0.0" "log" (func $log (param i32 i32 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 4096))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get 3)))
    (local.get $old))
  (data (i32.const 1024) "hello")
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32)
    (call $log
      (i32.sub (i32.load8_u (local.get 0)) (i32.const 48))
      (i32.const 1024) (i32.const 5) (i32.const 0) (i32.const 0) (i32.const 0))
    (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-event") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#;

#[test]
fn scoped_log_crosses_the_real_engine_and_revocation_refuses_later_calls() {
    let bytes = crate::engine::test_component::component(wat::parse_str(COMPONENT).unwrap());
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let artifact = backend.compile(&bytes, "@acme/scoped-log").unwrap();
    assert_eq!(artifact.imports(), ["synra:plugin/host#log"]);
    let host = Arc::new(Stub::default());
    // WIT enum ordinals: info = 2, warn = 3, error = 4.
    for (grant, level, allowed) in [
        (Some("log:info"), "2", true),
        (Some("log:info"), "3", false),
        (None, "2", false),
        (Some("log:*"), "4", true),
    ] {
        let mut grants = CapabilitySet::new();
        if let Some(grant) = grant {
            grants.insert_str(grant).unwrap();
        }
        // A denied void WIT call traps; each scenario therefore uses a fresh instance.
        let mut instance = Backend::new(backend.clone())
            .instantiate(artifact.as_ref())
            .unwrap();
        instance.set_session(LinkerSession::new(
            PluginId::parse("@acme/scoped-log").unwrap(),
            grants,
            Arc::new(Budget::new(Quota::default())),
            host.clone(),
        ));
        let result = instance
            .call(
                &Work::Activate {
                    config_json: level.to_owned(),
                },
                CallBudget::from_quota(&Quota::default()),
            )
            .unwrap();
        if allowed {
            assert!(matches!(result, CallOutcome::Ok(_)), "{result:?}");
        } else {
            assert!(
                matches!(result, CallOutcome::Trap { ref detail } if detail.contains(crate::CallError::CAPABILITY_DENIED)),
                "{result:?}"
            );
        }
        assert_eq!(instance.host_calls(), 1);
    }
    assert_eq!(host.called(), ["log", "log"]);
}

#[test]
fn a_real_host_trap_keeps_its_kind_when_its_message_names_budgets() {
    let bytes = crate::engine::test_component::component(wat::parse_str(COMPONENT).unwrap());
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let artifact = backend.compile(&bytes, "@acme/host-traps").unwrap();
    let mut instance = Backend::new(backend)
        .instantiate(artifact.as_ref())
        .unwrap();
    let mut grants = CapabilitySet::new();
    grants.insert_str("log:info").unwrap();
    let quota = Quota::default();
    let message = "the logger rejected fuel, epoch and interrupt fields";
    let host = Arc::new(Stub {
        log_failure: Some(crate::CallError::new(
            crate::CallError::HOST_FAILED,
            message,
        )),
        ..Stub::default()
    });
    instance.set_session(LinkerSession::new(
        PluginId::parse("@acme/host-traps").unwrap(),
        grants,
        Arc::new(Budget::new(quota.clone())),
        host.clone(),
    ));
    let outcome = instance
        .call(
            &Work::Activate {
                config_json: "2".to_owned(),
            },
            CallBudget::from_quota(&quota),
        )
        .unwrap();
    let error = outcome.into_result().expect_err("the host call trapped");
    assert_eq!(error.code, synra_protocol::ErrorCode::PluginTrapped);
    assert_eq!(
        error.details,
        Some(Box::new(serde_json::json!({"kind":"trap"})))
    );
    assert!(
        error.message.contains(crate::CallError::HOST_FAILED),
        "{error}"
    );
    assert!(error.message.contains(message), "{error}");
    assert_eq!(host.called(), ["log"]);
}
