//! Real WIT event calls bind the complete package identity and concrete event grant.

use std::sync::Arc;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

use crate::engine::{
    Backend, BackendKind, CallBudget, CallOutcome, LinkerSession, WasmBackend, WasmtimeBackend,
    Work,
};
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;

const COMPONENT: &str = r#"
(module
  (import "synra:plugin/host@1.0.0" "event-emit" (func $emit (param i32 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 4096))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $next))
    (global.set $next (i32.add (global.get $next) (i32.mul (local.get 3) (i32.const 4))))
    (local.get $old))
  (data (i32.const 1024) "{}")
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32)
    ;; Config is a JSON string containing an ASCII event name; omit its two quotes.
    (call $emit (i32.add (local.get 0) (i32.const 1)) (i32.sub (local.get 1) (i32.const 2))
      (i32.const 1024) (i32.const 2) (i32.const 2048))
    (i32.const 2048))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#;

#[test]
fn scoped_events_bind_real_guest_calls_to_package_identity_and_current_grants() {
    let bytes = crate::engine::test_component::component(wat::parse_str(COMPONENT).unwrap());
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let artifact = backend.compile(&bytes, "@acme/chat").unwrap();
    assert_eq!(artifact.imports(), ["synra:plugin/host#event-emit"]);
    let mut instance = Backend::new(backend)
        .instantiate(artifact.as_ref())
        .unwrap();
    let host = Arc::new(Stub::default());
    for (plugin, grant, event, expected) in [
        (
            "@acme/chat",
            Some("event:emit:_plugin.@acme/chat.ready"),
            "_plugin.@acme/chat.ready",
            None,
        ),
        (
            "@acme/chat",
            Some("event:emit:_plugin.@acme/chat.ready"),
            "_plugin.@acme/chat.other",
            Some(crate::CallError::CAPABILITY_DENIED),
        ),
        (
            "@other/chat",
            Some("event:emit:*"),
            "_plugin.@acme/chat.ready",
            Some(crate::CallError::CAPABILITY_DENIED),
        ),
        (
            "@acme/synra-plugin-chat",
            Some("event:emit:*"),
            "_plugin.@acme/chat.ready",
            Some(crate::CallError::CAPABILITY_DENIED),
        ),
        (
            "@acme/chat",
            None,
            "_plugin.@acme/chat.ready",
            Some(crate::CallError::CAPABILITY_DENIED),
        ),
        (
            "@acme/chat",
            Some("event:emit:_plugin.@acme/chat.*"),
            "_plugin.@acme/chat.ready",
            None,
        ),
        (
            "@acme/chat",
            Some("event:emit:*"),
            "_plugin.chat.ready",
            Some(crate::CallError::BAD_ARGUMENT),
        ),
    ] {
        let mut grants = CapabilitySet::new();
        if let Some(grant) = grant {
            grants.insert_str(grant).unwrap();
        }
        instance.set_session(LinkerSession::new(
            PluginId::parse(plugin).unwrap(),
            grants,
            Arc::new(Budget::new(Quota::default())),
            host.clone(),
        ));
        let result = instance
            .call(
                &Work::Activate {
                    config_json: serde_json::to_string(event).unwrap(),
                },
                CallBudget::from_quota(&Quota::default()),
            )
            .unwrap();
        match expected {
            None => assert!(matches!(result, CallOutcome::Ok(_)), "{result:?}"),
            Some(expected) => assert!(
                matches!(result, CallOutcome::Failed { ref code, .. } if code == expected),
                "{result:?}"
            ),
        }
    }
    assert_eq!(host.called(), ["event-emit", "event-emit"]);
    assert_eq!(instance.host_calls(), 7);
}
