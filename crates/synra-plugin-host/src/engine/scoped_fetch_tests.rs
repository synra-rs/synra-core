//! A real component calls the typed network import with a scoped, then revoked session.

use crate::engine::{
    Backend, BackendKind, CallBudget, CallOutcome, LinkerSession, WasmBackend, WasmtimeBackend,
    Work,
};
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;
use std::sync::Arc;
use synra_capability::CapabilitySet;
use synra_protocol::ids::PluginId;

const COMPONENT: &str = r#"
(module
  (import "synra:plugin/host@1.0.0" "network-fetch" (func $fetch (param i32 i32 i32)))
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 4096))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $next))
    (global.set $next (i32.add (global.get $next) (i32.mul (local.get 3) (i32.const 4))))
    (local.get $old))
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32)
    (call $fetch (local.get 0) (local.get 1) (i32.const 1024))
    (i32.const 1024))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#;

#[test]
fn scoped_fetch_crosses_the_real_engine_and_revocation_refuses_later_calls() {
    let bytes = crate::engine::test_component::component(wat::parse_str(COMPONENT).unwrap());
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let artifact = backend.compile(&bytes, "@acme/scoped").unwrap();
    assert_eq!(artifact.imports(), ["synra:plugin/host#network-fetch"]);
    let mut instance = Backend::new(backend)
        .instantiate(artifact.as_ref())
        .unwrap();
    let host = Arc::new(Stub::default());
    let mut grants = CapabilitySet::new();
    grants.insert_str("network:fetch:api.github.com").unwrap();
    for (authority, url, allowed) in [
        (grants.clone(), "https://api.github.com/", true),
        (grants, "https://evil.example/", false),
        (CapabilitySet::new(), "https://api.github.com/", false),
    ] {
        instance.set_session(LinkerSession::new(
            PluginId::parse("@acme/scoped").unwrap(),
            authority,
            Arc::new(Budget::new(Quota::default())),
            host.clone(),
        ));
        let result = instance
            .call(
                &Work::Activate {
                    config_json: serde_json::json!({"url": url}).to_string(),
                },
                CallBudget::from_quota(&Quota::default()),
            )
            .unwrap();
        if allowed {
            assert!(matches!(result, CallOutcome::Ok(_)), "{result:?}");
        } else {
            assert!(
                matches!(result, CallOutcome::Failed { ref code, .. } if code == crate::CallError::CAPABILITY_DENIED),
                "{result:?}"
            );
        }
    }
    assert_eq!(host.called(), ["network-fetch"]);
    assert_eq!(instance.host_calls(), 3);
}
