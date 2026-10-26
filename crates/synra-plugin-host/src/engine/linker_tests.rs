//! The linker is checked against the real WIT world and the shared host-call dispatcher.

use super::*;
use crate::engine::session::LinkerSession;
use crate::engine::wasmtime_backend::bindings::synra::plugin::{host::Host, types};
use crate::engine::{Backend, BackendKind, WasmBackend, WasmtimeBackend};
use crate::quota::{Budget, Quota};
use crate::test_host::Stub;
use std::sync::Arc;
use synra_capability::CapabilitySet;
use synra_protocol::ids::PluginId;

fn state(grants: &[&str], host: Arc<Stub>) -> StoreData {
    let mut capabilities = CapabilitySet::new();
    for grant in grants {
        capabilities.insert_str(grant).unwrap();
    }
    let mut state = StoreData::new();
    state.session = Some(Box::new(LinkerSession::new(
        PluginId::parse("@acme/bridge").unwrap(),
        capabilities,
        Arc::new(Budget::new(Quota::default())),
        host,
    )));
    state
}

#[test]
fn the_complete_production_wit_world_instantiates_against_the_real_linker() {
    let component = crate::engine::test_component::dummy_world();
    let backend = Arc::new(WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap());
    let artifact = backend.compile(&component, "@acme/full-world").unwrap();
    if let Err(error) = Backend::new(backend).instantiate(artifact.as_ref()) {
        panic!("the complete WIT component did not instantiate: {error}");
    }
}

#[test]
fn typed_outcomes_preserve_the_gate_error_and_do_not_reach_the_host() {
    let host = Arc::new(Stub::default());
    let mut data = state(&[], Arc::clone(&host));
    let answer = data.storage_get("known".to_owned()).unwrap();
    let types::Outcome::Err(error) = answer else {
        panic!("permission refusal expected")
    };
    assert_eq!(error.code, CallError::CAPABILITY_DENIED);
    assert!(!error.message.is_empty());
    assert!(host.called().is_empty());
    assert_eq!(data.host_calls, 1);
}

#[test]
fn typed_storage_results_include_payloads_and_actual_host_calls_only() {
    let host = Arc::new(Stub::default());
    let mut data = state(&["storage:local:read"], Arc::clone(&host));
    let answer = data.storage_get("known".to_owned()).unwrap();
    assert!(matches!(answer, types::Outcome::Ok(text) if text == "a value"));
    assert_eq!(host.called(), ["storage-get"]);
    assert_eq!(data.host_calls, 1);
}

#[test]
fn typed_device_lists_and_quota_are_not_flattened_into_other_component_types() {
    let host = Arc::new(Stub::with_devices(&[("device", "Desktop", "desktop")]));
    let mut data = state(&["device:list", "storage:local:read"], Arc::clone(&host));
    let devices = data.device_list().unwrap();
    assert_eq!(devices.len(), 1);
    let device = devices.first().unwrap();
    assert_eq!(device.id, "device");
    assert!(matches!(device.kind, types::DeviceKind::Desktop));
    let quota = data.storage_quota().unwrap();
    assert_eq!(quota.0, 0);
    assert_eq!(quota.1, Quota::default().max_storage_bytes);
}

#[test]
fn calls_without_a_session_fail_closed_and_still_count_as_host_attempts() {
    let mut data = StoreData::new();
    assert!(data.env_sdk_version().is_err());
    assert!(matches!(
        data.storage_get("known".to_owned()).unwrap(),
        types::Outcome::Err(_)
    ));
    assert_eq!(data.host_calls, 2);
}

#[test]
fn typed_argument_adapters_preserve_multi_argument_meanings_and_string_payloads() {
    let host = Arc::new(Stub::default());
    let grants = host_surface::CAPABILITIES;
    let mut data = state(grants, Arc::clone(&host));
    let payload = "{\"text\":\"你好\\nquoted\"}".to_owned();
    let answer = data
        .device_send(
            "peer".to_owned(),
            "_plugin.bridge.arrived".to_owned(),
            payload.clone(),
        )
        .unwrap();
    assert!(matches!(&answer, types::Outcome::Ok(_)), "{answer:?}");
    assert!(matches!(
        data.transfer_send("file".to_owned(), "peer".to_owned(), payload.clone())
            .unwrap(),
        types::Outcome::Ok(_)
    ));
    assert!(matches!(
        data.action_declare("render".to_owned(), payload.clone())
            .unwrap(),
        types::Outcome::Ok(_)
    ));
    assert!(matches!(
        data.action_invoke(
            "@acme/target".to_owned(),
            "render".to_owned(),
            payload.clone()
        )
        .unwrap(),
        types::Outcome::Ok(_)
    ));
    let seen = host.seen.lock().unwrap().clone();
    assert!(seen.contains(&(
        "device-send".to_owned(),
        format!("peer/_plugin.bridge.arrived/{payload}")
    )));
    assert!(seen.contains(&("transfer-send".to_owned(), format!("file/peer/{payload}"))));
    assert!(seen.contains(&("action-declare".to_owned(), format!("render/{payload}"))));
    assert!(seen.contains(&(
        "action-invoke".to_owned(),
        format!("@acme/target/render/{payload}")
    )));
    assert_eq!(data.host_calls, 4);
}

#[test]
fn typed_lists_preserve_optional_prefixes_and_invalid_device_kinds_are_refused() {
    let host = Arc::new(Stub::with_devices(&[(
        "device",
        "Unknown",
        "not-a-wit-kind",
    )]));
    let grants = host_surface::CAPABILITIES;
    let mut data = state(grants, host);
    assert_eq!(
        data.storage_keys(Some("前缀/".to_owned())).unwrap(),
        ["前缀/one", "前缀/two"]
    );
    assert_eq!(data.storage_keys(None).unwrap(), ["one", "two"]);
    assert_eq!(
        data.action_list().unwrap(),
        r#"[{"plugin":"@acme/other","name":"greet"}]"#
    );
    assert!(data.device_list().is_err());
}

#[test]
fn an_import_with_a_matching_name_and_wrong_result_type_is_refused_at_linking() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap();
    let binary = wat::parse_str(
        r#"(component
          (import "synra:plugin/host@1.0.0" (instance
            (export "storage-get" (func (param "key" string) (result string)))))
          (instance $lifecycle)
          (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle)))"#,
    )
    .unwrap();
    let artifact = backend.compile(&binary, "@acme/wrong-host-abi").unwrap();
    let error = match Backend::new(Arc::new(backend)).instantiate(artifact.as_ref()) {
        Ok(_) => panic!("a familiar import name must not bypass WIT type checking"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("storage-get"), "{error}");
    assert!(error.contains("type mismatch"), "{error}");
}

#[test]
fn a_constructor_that_never_returns_is_stopped_by_its_startup_budget() {
    use crate::engine::executor::{Epoch, EpochTicker};
    let epoch = Epoch::new();
    let _ticker = EpochTicker::start(epoch.clone());
    let backend = Arc::new(
        WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, epoch.clone()).unwrap(),
    );
    let binary = wat::parse_str(
        r#"(component
      (core module $m (func $start (loop $again (br $again))) (start $start))
      (core instance $i (instantiate $m))
      (instance $lifecycle)
      (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle)))"#,
    )
    .unwrap();
    let artifact = backend.compile(&binary, "@acme/spinning-start").unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let detail = match Backend::new(backend).instantiate(artifact.as_ref()) {
            Ok(_) => panic!("an infinite constructor must not instantiate"),
            Err(error) => error.to_string(),
        };
        sender.send(detail).unwrap();
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(3));
    if result.is_err() {
        // Independent interruption keeps a broken fuel test from leaving a runaway worker.
        for _ in 0..1024 {
            epoch.advance();
        }
    }
    worker.join().unwrap();
    let detail = result.expect("startup must finish within its budget");
    assert!(
        detail.contains("fuel") || detail.contains("interrupt"),
        "{detail}"
    );
}
