use super::super::tests::{ANSWERS, backend_and_executor, compile, instantiate};
use super::*;
use crate::engine::types::CallBudget;

fn works() -> Vec<Work> {
    vec![
        Work::Activate {
            config_json: "{}".to_owned(),
        },
        Work::Tick {
            tick_json: "{}".to_owned(),
        },
        Work::Migrate {
            from_version: "1".to_owned(),
            to_version: "2".to_owned(),
        },
        Work::Execute {
            action: "run".to_owned(),
            args_json: "{}".to_owned(),
        },
        Work::InvokeAction {
            name: "run".to_owned(),
            args_json: "{}".to_owned(),
        },
    ]
}

fn component(failed: bool, details: Option<&str>) -> String {
    let flag = u8::from(failed);
    let details_flag = u8::from(details.is_some());
    let details = details.unwrap_or_default();
    let details_len = details.len();
    let details_data: String = details
        .bytes()
        .map(|byte| format!("\\{byte:02x}"))
        .collect();
    format!(
        r#"
(component
  (type $error (record (field "code" string) (field "message" string) (field "details" (option string))))
  (type $outcome (variant (case "ok" string) (case "err" $error)))
  (core module $m
    (memory (export "memory") 1)
    (data (i32.const 1024) "guest result")
    (data (i32.const 1100) "pluginRefused")
    (data (i32.const 1200) "intent rejected")
    (data (i32.const 1300) "{details_data}")
    (global $next (mut i32) (i32.const 4096))
    (global $active (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ptr i32)
      (local.set $ptr (global.get $next))
      (global.set $next (i32.add (local.get $ptr) (local.get 3)))
      (local.get $ptr))
    (func $answer (result i32)
      (if (global.get $active) (then (unreachable)))
      (global.set $active (i32.const 1))
      (i32.store8 (i32.const 2048) (i32.const {flag}))
      (if (i32.const {flag})
        (then
          (i32.store (i32.const 2052) (i32.const 1100))
          (i32.store (i32.const 2056) (i32.const 13))
          (i32.store (i32.const 2060) (i32.const 1200))
          (i32.store (i32.const 2064) (i32.const 15))
          (i32.store8 (i32.const 2068) (i32.const {details_flag}))
          (i32.store (i32.const 2072) (i32.const 1300))
          (i32.store (i32.const 2076) (i32.const {details_len})))
        (else
          (i32.store (i32.const 2052) (i32.const 1024))
          (i32.store (i32.const 2056) (i32.const 12))))
      (i32.const 2048))
    (func (export "one") (param i32 i32) (result i32) (call $answer))
    (func (export "two") (param i32 i32 i32 i32) (result i32) (call $answer))
    (func (export "finish") (param i32)
      (if (i32.ne (global.get $active) (i32.const 1)) (then (unreachable)))
      (global.set $active (i32.const 0))))
  (core instance $i (instantiate $m))
  (func $activate (param "config-json" string) (result $outcome)
    (canon lift (core func $i "one") (memory (core memory $i "memory"))
      (realloc (core func $i "realloc")) (post-return (core func $i "finish"))))
  (func $tick (param "tick-json" string) (result $outcome)
    (canon lift (core func $i "one") (memory (core memory $i "memory"))
      (realloc (core func $i "realloc")) (post-return (core func $i "finish"))))
  (func $migrate (param "from-version" string) (param "to-version" string) (result $outcome)
    (canon lift (core func $i "two") (memory (core memory $i "memory"))
      (realloc (core func $i "realloc")) (post-return (core func $i "finish"))))
  (func $execute (param "action" string) (param "args-json" string) (result $outcome)
    (canon lift (core func $i "two") (memory (core memory $i "memory"))
      (realloc (core func $i "realloc")) (post-return (core func $i "finish"))))
  (func $invoke (param "name" string) (param "args-json" string) (result $outcome)
    (canon lift (core func $i "two") (memory (core memory $i "memory"))
      (realloc (core func $i "realloc")) (post-return (core func $i "finish"))))
  (instance $lifecycle (export "error" (type $error)) (export "outcome" (type $outcome)) (export "activate" (func $activate)) (export "migrate" (func $migrate)) (export "on-tick" (func $tick)))
  (instance $share (export "error" (type $error)) (export "outcome" (type $outcome)) (export "execute" (func $execute)))
  (instance $actions (export "error" (type $error)) (export "outcome" (type $outcome)) (export "invoke" (func $invoke)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
  (export "synra:plugin/share@1.0.0" (instance $share))
  (export "synra:plugin/actions@1.0.0" (instance $actions)))
"#
    )
}

#[test]
fn every_outcome_entry_lifts_success_and_failure_and_runs_post_return_before_reuse() {
    for (failed, details) in [
        (false, None),
        (true, None),
        (true, Some("")),
        (
            true,
            Some(r#"{"kind":"timeout","label":"中文🖱️","cleanupPending":true}"#),
        ),
        (true, Some("null")),
        (true, Some("not-json")),
    ] {
        let (backend, _executor) = backend_and_executor();
        let artifact = compile(&backend, &component(failed, details), "@acme/outcomes");
        let mut instance = instantiate(&backend, artifact.as_ref());
        for _ in 0..2 {
            for work in works() {
                let result = instance.call(&work, CallBudget::unlimited()).unwrap();
                assert_eq!(
                    result,
                    if failed {
                        CallOutcome::Failed {
                            code: "pluginRefused".to_owned(),
                            message: "intent rejected".to_owned(),
                            details: details.map(str::to_owned),
                        }
                    } else {
                        CallOutcome::Ok("guest result".to_owned())
                    }
                );
                assert_eq!(instance.host_calls(), 0);
            }
        }
    }
}

#[test]
fn a_result_signature_mismatch_is_refused_before_guest_instructions_run() {
    let (backend, _executor) = backend_and_executor();
    let fixture = ANSWERS.replace("(result string)", "(result bool)");
    assert_ne!(fixture, ANSWERS);
    let artifact = compile(&backend, &fixture, "@acme/wrong-type");
    let mut instance = instantiate(&backend, artifact.as_ref());
    let result = instance
        .call(
            &Work::CanHandle {
                item_json: "{}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .unwrap();
    assert!(matches!(result, CallOutcome::Trap { .. }));
    assert_eq!(instance.last_fuel_consumed(), Some(0));
    assert_eq!(instance.host_calls(), 0);
}

#[test]
fn post_return_failure_cannot_be_reported_as_a_successful_guest_answer() {
    let (backend, _executor) = backend_and_executor();
    let fixture =
        component(false, None).replace("(global.set $active (i32.const 0))", "(unreachable)");
    assert_ne!(fixture, component(false, None));
    let artifact = compile(&backend, &fixture, "@acme/bad-cleanup");
    let mut instance = instantiate(&backend, artifact.as_ref());
    let result = instance
        .call(
            &works().into_iter().next().unwrap(),
            CallBudget::unlimited(),
        )
        .unwrap();
    assert!(matches!(result, CallOutcome::Trap { .. }));
}
mod host;
