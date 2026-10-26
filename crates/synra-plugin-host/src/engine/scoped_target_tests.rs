//! Concrete target grants through typed production WIT imports and current linker sessions.

use std::sync::Arc;

use synra_capability::CapabilitySet;
use synra_protocol::PluginId;

use crate::engine::{
    Backend, BackendKind, CallBudget, CallOutcome, LinkerSession, WasmBackend, WasmtimeBackend,
    Work,
};
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;

fn escaped(text: &str) -> String {
    text.bytes().map(|byte| format!("\\{byte:02x}")).collect()
}

fn component(import: &str, args: [&str; 3]) -> Vec<u8> {
    let [first, second, third] = args;
    let a = escaped(first);
    let b = escaped(second);
    let c = escaped(third);
    let alen = first.len();
    let blen = second.len();
    let clen = third.len();
    let (parameters, third_argument) = if import == "action-declare" {
        ("i32 i32 i32 i32 i32", String::new())
    } else {
        (
            "i32 i32 i32 i32 i32 i32 i32",
            format!("(i32.const 3072) (i32.const {clen})"),
        )
    };
    let wat = format!(
        r#"
(module
  (import "synra:plugin/host@1.0.0" "{import}" (func $call (param {parameters})))
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 8192))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $next))
    (global.set $next (i32.add (global.get $next) (i32.mul (local.get 3) (i32.const 4))))
    (local.get $old))
  (data (i32.const 1024) "{a}")
  (data (i32.const 2048) "{b}")
  (data (i32.const 3072) "{c}")
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32)
    (call $call (i32.const 1024) (i32.const {alen}) (i32.const 2048) (i32.const {blen})
      {third_argument} (i32.const 4096))
    (i32.const 4096))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#
    );
    crate::engine::test_component::component(wat::parse_str(wat).expect("module"))
}

fn scoped_calls(import: &str, args: [&str; 3], cases: &[(Option<&str>, bool)]) {
    let bytes = component(import, args);
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("engine"));
    let artifact = backend.compile(&bytes, "@acme/chat").expect("compiled");
    let full_import = format!("synra:plugin/host#{import}");
    assert_eq!(artifact.imports(), [full_import]);
    let mut instance = Backend::new(backend)
        .instantiate(artifact.as_ref())
        .expect("instance");
    let host = Arc::new(Stub::default());
    let mut count = 0;
    for (grant, allowed) in cases {
        let grants = CapabilitySet::parse_all(grant.iter().copied()).expect("grants");
        if *allowed {
            assert!(crate::undeclared_imports(artifact.imports(), &grants).is_empty());
        }
        // The same compiled instance gets a fresh current session; a removed grant cannot survive in it.
        instance.set_session(LinkerSession::new(
            PluginId::parse("@acme/chat").expect("plugin"),
            grants,
            Arc::new(Budget::new(Quota::default())),
            host.clone(),
        ));
        let result = instance
            .call(
                &Work::Activate {
                    config_json: "{}".to_owned(),
                },
                CallBudget::from_quota(&Quota::default()),
            )
            .expect("call");
        if *allowed {
            assert!(
                matches!(result, CallOutcome::Ok(_)),
                "{grant:?}: {result:?}"
            );
            count += 1;
        } else {
            assert!(
                matches!(result, CallOutcome::Failed { ref code, .. } if code == crate::CallError::CAPABILITY_DENIED),
                "{grant:?}: {result:?}"
            );
        }
        assert_eq!(
            host.called().len(),
            count,
            "a refusal cannot reach the host"
        );
    }
    assert_eq!(instance.host_calls(), cases.len() as u64);
}

#[test]
fn scoped_target_device_calls_recheck_the_current_grant_on_a_reused_instance() {
    scoped_calls(
        "device-send",
        [
            "00000000-0000-4000-8000-000000000001",
            "_plugin.@acme/chat.ready",
            "{}",
        ],
        &[
            (
                Some("device:send:00000000-0000-4000-8000-000000000001"),
                true,
            ),
            (
                Some("device:send:00000000-0000-4000-8000-000000000002"),
                false,
            ),
            (None, false),
            (Some("device:send:*"), true),
        ],
    );
}

#[test]
fn scoped_target_declarations_authorize_the_name_before_registration() {
    scoped_calls(
        "action-declare",
        ["format-date", "{}", ""],
        &[
            (Some("action:declare:format-date"), true),
            (Some("action:declare:other"), false),
            (None, false),
            (Some("action:declare:*"), true),
            (Some("action:declare"), false),
        ],
    );
}

#[test]
fn scoped_target_action_calls_keep_both_package_and_name_in_the_authority() {
    scoped_calls(
        "action-invoke",
        ["@acme/formatter", "format-date", "{}"],
        &[
            (Some("action:invoke:@acme/formatter:format-date"), true),
            (Some("action:invoke:@other/formatter:format-date"), false),
            (Some("action:invoke:@acme/formatter:other"), false),
            (None, false),
            (Some("action:invoke:@acme/formatter:*"), true),
            (Some("action:invoke:*:format-date"), true),
            (Some("action:invoke:*"), false),
        ],
    );
}
