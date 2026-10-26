//! Clipboard values travel through a real WIT import and the production call dispatcher.

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
  (import "synra:plugin/host@1.0.0" "platform-read-clipboard" (func $read (param i32)))
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 4096))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $old i32)
    (local.set $old (global.get $next))
    (global.set $next (i32.add (global.get $next) (i32.mul (local.get 3) (i32.const 4))))
    (local.get $old))
  (func (export "synra:plugin/lifecycle@1.0.0#activate") (param i32 i32) (result i32)
    (call $read (i32.const 2048))
    (i32.const 2048))
  (func (export "synra:plugin/lifecycle@1.0.0#deactivate"))
  (func (export "synra:plugin/lifecycle@1.0.0#migrate") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/lifecycle@1.0.0#on-tick") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#can-handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/share@1.0.0#execute") (param i32 i32 i32 i32) (result i32) (i32.const 0))
  (func (export "synra:plugin/actions@1.0.0#invoke") (param i32 i32 i32 i32) (result i32) (i32.const 0)))
"#;

#[test]
fn clipboard_json_distinguishes_absence_empty_text_and_literal_json_through_wasm() {
    let bytes = crate::engine::test_component::component(wat::parse_str(COMPONENT).unwrap());
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let artifact = backend.compile(&bytes, "@acme/chat").unwrap();
    assert_eq!(
        artifact.imports(),
        ["synra:plugin/host#platform-read-clipboard"]
    );
    let mut instance = Backend::new(backend)
        .instantiate(artifact.as_ref())
        .unwrap();
    for value in [None, Some(""), Some("null"), Some("\"quoted\"\r\n中文🖱️\\")] {
        let host = Arc::new(Stub {
            clipboard: Some(value.map(str::to_owned)),
            ..Stub::default()
        });
        for granted in [true, false] {
            let mut grants = CapabilitySet::new();
            if granted {
                grants.insert_str("platform:read-clipboard").unwrap();
            }
            instance.set_session(LinkerSession::new(
                PluginId::parse("@acme/chat").unwrap(),
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
                .unwrap();
            if granted {
                let CallOutcome::Ok(answer) = result else {
                    panic!("{result:?}")
                };
                assert_eq!(answer, serde_json::to_string(&value).unwrap());
                assert_eq!(
                    serde_json::from_str::<Option<String>>(&answer)
                        .unwrap()
                        .as_deref(),
                    value
                );
            } else {
                assert!(
                    matches!(result, CallOutcome::Failed { ref code, .. } if code == crate::CallError::CAPABILITY_DENIED),
                    "{result:?}"
                );
            }
            assert_eq!(
                host.called(),
                ["platform"],
                "a denied read must not reach the host"
            );
        }
    }
    assert_eq!(instance.host_calls(), 8);
}
