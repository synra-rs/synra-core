//! The public SDK's compiled Rust guest, run through the production backend.

use super::{Backend, BackendKind, CallBudget, CallOutcome, WasmBackend, WasmtimeBackend, Work};
use crate::engine::session::LinkerSession;
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;
use std::sync::Arc;
use synra_capability::CapabilitySet;
use synra_protocol::ids::PluginId;

#[test]
fn rust_guest_round_trips_through_the_sdk_and_generated_host() {
    let path = std::env::var_os("SYNRA_RUST_GUEST")
        .expect("set SYNRA_RUST_GUEST to the freshly built wasm32-unknown-unknown SDK core module");
    let module = std::fs::read(path).expect("the compiled Rust guest core module");
    let bytes = wit_component::ComponentEncoder::default()
        .module(&module)
        .unwrap()
        .validate(true)
        .encode()
        .unwrap();
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let compiled = backend.compile(&bytes, "@acme/rust-guest").unwrap();
    assert_eq!(
        compiled.imports(),
        [
            "synra:plugin/host#env-sdk-version",
            "synra:plugin/host#platform-open-url"
        ]
    );
    let mut instance = Backend::new(backend)
        .instantiate(compiled.as_ref())
        .unwrap();
    let host = Arc::new(Stub::default());
    let mut grants = CapabilitySet::new();
    grants.insert_str("platform:open-url").unwrap();
    instance.set_session(LinkerSession::new(
        PluginId::parse("@acme/rust-guest").unwrap(),
        grants,
        Arc::new(Budget::new(Quota::default())),
        host.clone(),
    ));
    let result = instance
        .call(
            &Work::Activate {
                config_json: "{}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .unwrap();
    assert_eq!(result, CallOutcome::Ok("1.0.0".to_owned()));
    assert_eq!(instance.host_calls(), 1);
    let event_json =
        serde_json::json!({"event":"_plugin.@acme/rust-guest.ready","payload":{"text":"中文🖱️"}})
            .to_string();
    let result = instance
        .call(
            &Work::Event {
                event_json: event_json.clone(),
            },
            CallBudget::unlimited(),
        )
        .unwrap();
    assert_eq!(result, CallOutcome::Ok(event_json));
    assert_eq!(instance.host_calls(), 1);
    let result = instance
        .call(
            &Work::CanHandle {
                item_json: "side-effect".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .unwrap();
    assert_eq!(
        result,
        CallOutcome::Ok(crate::host_calls::CallError::SIDE_EFFECT_NOT_ALLOWED.to_owned())
    );
    assert!(host.called().is_empty());
    assert_eq!(instance.host_calls(), 2);
    for _ in 0..2 {
        let result = instance
            .call(
                &Work::Execute {
                    action: "open".to_owned(),
                    args_json: "https://example.invalid/".to_owned(),
                },
                CallBudget::unlimited(),
            )
            .unwrap();
        assert_eq!(result, CallOutcome::Ok("null".to_owned()));
    }
    assert_eq!(host.called(), ["platform", "platform"]);
    assert_eq!(instance.host_calls(), 4);
    let result = instance
        .call(
            &Work::Execute {
                action: "unknown".to_owned(),
                args_json: "{}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .unwrap();
    assert_eq!(
        result,
        CallOutcome::Failed {
            code: "notMine".to_owned(),
            message: "this plugin handles nothing".to_owned(),
            details: None,
        }
    );
    assert_eq!(instance.host_calls(), 4);
}
