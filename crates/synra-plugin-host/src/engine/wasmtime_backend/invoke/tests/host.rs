use super::{backend_and_executor, instantiate};
use crate::engine::session::LinkerSession;
use crate::engine::types::{CallBudget, CallOutcome, Work};
use crate::host_calls::CallError;
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;
use std::sync::Arc;
use synra_capability::CapabilitySet;
use synra_protocol::ids::PluginId;

fn fixture(write: bool) -> Vec<u8> {
    let name = if write { "storage-set" } else { "storage-get" };
    let lowered = if write {
        "i32 i32 i32 i32 i32"
    } else {
        "i32 i32 i32"
    };
    let arguments = if write {
        "(i32.const 1024) (i32.const 5) (i32.const 1100) (i32.const 7) (i32.const 2048)"
    } else {
        "(i32.const 1024) (i32.const 5) (i32.const 2048)"
    };
    let module = format!(
        r#"
(module
  (import "synra:plugin/host@1.0.0" "{name}" (func $operation (param {lowered})))
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 4096))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $at i32)
    (local.set $at (global.get $next))
    (global.set $next (i32.add (local.get $at) (local.get 3)))
    (local.get $at))
  (data (i32.const 1024) "known")
  (data (i32.const 1100) "written")
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32)
    (call $operation {arguments})
    (i32.const 2052))
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-event") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#
    );
    crate::engine::test_component::component(wat::parse_str(module).unwrap())
}

fn session(host: Arc<Stub>, grants: &[&str]) -> LinkerSession {
    let mut capabilities = CapabilitySet::new();
    for grant in grants {
        capabilities.insert_str(grant).unwrap();
    }
    LinkerSession::new(
        PluginId::parse("@acme/host-wire").unwrap(),
        capabilities,
        Arc::new(Budget::new(Quota::default())),
        host,
    )
}

#[test]
fn a_real_guest_receives_typed_host_outcomes_and_only_counts_import_attempts() {
    let (backend, _executor) = backend_and_executor();
    let artifact =
        crate::WasmBackend::compile(backend.as_ref(), &fixture(false), "@acme/host-read").unwrap();
    let mut instance = instantiate(&backend, artifact.as_ref());
    let work = Work::CanHandle {
        item_json: "{}".to_owned(),
    };
    assert_eq!(
        instance.call(&work, CallBudget::unlimited()).unwrap(),
        CallOutcome::Ok(CallError::HOST_FAILED.to_owned())
    );
    assert_eq!(instance.host_calls(), 1);
    let host = Arc::new(Stub::default());
    instance.set_session(session(Arc::clone(&host), &[]));
    assert_eq!(
        instance.call(&work, CallBudget::unlimited()).unwrap(),
        CallOutcome::Ok(CallError::CAPABILITY_DENIED.to_owned())
    );
    assert!(host.called().is_empty());
    assert_eq!(instance.host_calls(), 2);
    instance.set_session(session(Arc::clone(&host), &["storage:local:read"]));
    assert_eq!(
        instance.call(&work, CallBudget::unlimited()).unwrap(),
        CallOutcome::Ok("a value".to_owned())
    );
    assert_eq!(host.called(), ["storage-get"]);
    assert_eq!(instance.host_calls(), 3);
}

#[test]
fn matching_cannot_write_even_with_a_write_grant_through_the_real_component_boundary() {
    let (backend, _executor) = backend_and_executor();
    let artifact =
        crate::WasmBackend::compile(backend.as_ref(), &fixture(true), "@acme/pure-host").unwrap();
    let mut instance = instantiate(&backend, artifact.as_ref());
    let host = Arc::new(Stub::default());
    instance.set_session(session(Arc::clone(&host), &["storage:local:write"]));
    let result = instance
        .call(
            &Work::CanHandle {
                item_json: "{}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .unwrap();
    assert_eq!(
        result,
        CallOutcome::Ok(CallError::SIDE_EFFECT_NOT_ALLOWED.to_owned())
    );
    assert!(host.called().is_empty());
    assert_eq!(instance.host_calls(), 1);
}
