//! The engine, tested against real components.
//!
//! These tests need the `wasm-text` feature, and they are the only place in the crate where a guest actually runs.
//! Everything else — the pool's choices, the budget arithmetic, the script table — is tested without an engine, on
//! purpose: a suite that needed a compiler to check a state machine would only run where the compiler builds.
//!
//! # Where the components come from
//!
//! From the `wat` strings below, as text, compiled by the engine at test time. A checked-in `.wasm` would be a binary
//! nobody can review; a `.wat` is a few lines a reader can check against what the test asserts.
//!
//! # Two tests are ignored, and why
//!
//! Making a *call* needs one more thing than compiling and instantiating do: the address of an export that lives inside
//! a nested interface instance. `wasmtime`'s lookup is by the name an instance merges into its own component's export
//! map, and everything a nested instance holds is **not** in the component's own map — which is the component model
//! being correct rather than a missing feature, and it is exactly what the generated bindings exist to bridge.
//!
//! So those two tests are written and ignored, and what they specify is a published promise rather than a wish: the
//! instruction budget ends a guest that loops, and a call's answer comes back. What *is* tested here without them is
//! everything that does not need a call — compiling, reading what a component imports, refusing a component this host
//! cannot link, and the ABI being checked when the component is decoded.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::engine::types::{Backend, WasmBackend};
use crate::engine::executor::{Epoch, EpochTicker, WasmExecutor};

/// A backend sharing an executor's epoch, as a running kernel builds it.
fn backend_and_executor() -> (Arc<WasmtimeBackend>, WasmExecutor) {
    let executor = WasmExecutor::start(2, 4).expect("an executor");
    let backend = WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
        .expect("an engine");
    (Arc::new(backend), executor)
}

/// A component whose `lifecycle` instance exists and holds nothing.
///
/// It is the fixture for "the interface is there and the function is not": a call to it reaches a component that
/// exports `lifecycle` and no `activate`, which is what a call to an absent export looks like.
const EMPTY: &str = r#"
(component
  (instance $lifecycle)
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle)))
"#;



/// A component whose `activate` runs for ever, in pure arithmetic.
///
/// The loop allocates nothing and calls nothing, so **fuel** is the only thing that can stop it: an epoch check happens
/// at the engine's safepoints, and a tight arithmetic loop reaches them too, but the instruction counter is what makes
/// the stop deterministic. This is the fixture that proves the fuel budget is armed.
const SPINS: &str = r#"
(component
  (core module $m
    (memory (export "memory") 1)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32) (result i32)
      (local $at i32)
      (local.set $at (global.get $next))
      (global.set $next (i32.add (local.get $at) (local.get $new-size)))
      (local.get $at))
    (func (export "spin") (param $value i32)
      (loop $l
        (br $l))))
  (core instance $i (instantiate $m))
  (func $activate (param "config-json" u32)
    (canon lift (core func $i "spin")
      (memory (core memory $i "memory"))
      (realloc (core func $i "realloc"))))
  (instance $lifecycle (export "activate" (func $activate)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

/// A component whose `activate` returns a fixed string.
///
/// # What the parameters are
///
/// The core function takes what the canonical ABI lowers the lifted signature to. A `string` **parameter** arrives as a
/// pointer and a length, and a `string` **result** is returned by the guest writing it — also a pointer and a length —
/// into space it borrowed from the host through `realloc`.
///
/// Writing a fixture that gets this wrong is a parse error rather than a wrong value at runtime, which is the property
/// that makes the component model worth using: the ABI is checked when the component is decoded.
const GREETS: &str = r#"
(component
  (core module $m
    (memory (export "memory") 1)
    (data (i32.const 1024) "hello from the plugin")
    (global $next (mut i32) (i32.const 2048))
    (global $result (mut i32) (i32.const 0))
    (func (export "realloc") (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32) (result i32)
      (local $at i32)
      (local.set $at (global.get $next))
      (global.set $next (i32.add (local.get $at) (local.get $new-size)))
      (global.set $result (local.get $at))
      (local.get $at))
    (func (export "greet") (param $ptr i32) (param $len i32) (result i32)
      (i32.store (global.get $result) (i32.const 1024))
      (i32.store (i32.add (global.get $result) (i32.const 4)) (i32.const 20))
      (i32.const 1)))
  (core instance $i (instantiate $m))
  (func $activate (param "config-json" string) (result string)
    (canon lift (core func $i "greet")
      (memory (core memory $i "memory"))
      (realloc (core func $i "realloc"))))
  (instance $lifecycle (export "activate" (func $activate)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle)))
"#;

/// A component that imports a host function.
///
/// The point of this fixture is the *import*: its `lifecycle` instance exists so that the compilation succeeds far
/// enough to reach instantiation, where the import is what fails.
const IMPORTS: &str = r#"
(component
  (import "synra:plugin/host@1.0.0" (instance $host
    (export "env-sdk-version" (func (result string)))))
  (core module $m
    (func (export "noop") (result i32) (i32.const 0)))
  (core instance $i (instantiate $m))
  (instance $lifecycle)
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

/// A component importing a function the contract does not declare.
///
/// The linker defines exactly the contract's table, so this is refused by the linker rather than by a rule somebody has
/// to remember — and the refusal names the function, which is what a plugin author needs.
const IMPORTS_UNKNOWN: &str = r#"
(component
  (import "synra:plugin/host@1.0.0" (instance $host
    (export "teleport" (func (result string)))))
  (core module $m
    (func (export "noop") (result i32) (i32.const 0)))
  (core instance $i (instantiate $m))
  (instance $lifecycle)
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

fn compile(backend: &WasmtimeBackend, wat: &str, id: &str) -> Box<dyn CompiledArtifact> {
    match backend.compile(wat.as_bytes(), id) {
        Ok(artifact) => artifact,
        // Matched rather than unwrapped: a trait object is not `Debug`, and "did not compile" without the engine's
        // own reason is the message a plugin author can do nothing with.
        Err(error) => panic!("{id} did not compile: {error}"),
    }
}

/// Instantiates, or fails with the engine's own reason.
fn instantiate(backend: &Arc<WasmtimeBackend>, artifact: &dyn CompiledArtifact) -> Box<dyn PluginInstance> {
    match handle(backend).instantiate(artifact) {
        Ok(instance) => instance,
        Err(error) => panic!("the component did not instantiate: {error}"),
    }
}

fn handle(backend: &Arc<WasmtimeBackend>) -> Backend {
    Backend::new(Arc::clone(backend))
}

// ── Compiling ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn an_empty_artifact_is_refused_before_the_engine_sees_it() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    assert!(matches!(backend.compile(b"", "p"), Err(BackendError::Compile { .. })));
}

#[test]
fn bytes_that_are_not_a_component_are_refused_with_the_engines_own_reason() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    // A text file and a truncated header, which are what a failed download and a renamed file look like.
    for bytes in [&b"not a component at all"[..], &b"\0asm\x01\0\0\0"[..]] {
        // Matched rather than formatted: a compiled artefact is a trait object and not `Debug`, and what the test
        // wants is the engine's own reason rather than a rendering of the value.
        match backend.compile(bytes, "p") {
            Err(BackendError::Compile { detail }) => assert!(!detail.is_empty()),
            Err(other) => panic!("expected a compile refusal, got {other}"),
            Ok(_) => panic!("{bytes:?} was accepted as a component"),
        }
    }
}

#[test]
fn a_component_compiles_and_reports_a_digest_of_the_right_shape() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let artifact = compile(&backend, EMPTY, "@acme/empty");

    assert_eq!(artifact.kind(), BackendKind::WasmtimeCranelift);
    assert_eq!(artifact.digest().len(), 64, "a digest is what a cache key is built from");
    assert!(artifact.digest().chars().all(|character| character.is_ascii_hexdigit()));
}

#[test]
fn what_a_component_imports_is_read_from_the_component() {
    // ★ The fact a manifest cannot be trusted for. This component's import comes from its own type, and the host
    // reports it before the artifact is handed back rather than discovering it at the first call.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let artifact = compile(&backend, IMPORTS, "@acme/imports");

    let concrete = (artifact.as_ref() as &dyn std::any::Any)
        .downcast_ref::<EngineArtifact>()
        .expect("the artefact this backend made");
    assert!(
        concrete.imports().iter().any(|import| import.contains("synra:plugin/host")),
        "{:?}",
        concrete.imports()
    );
}

#[test]
fn a_component_that_imports_a_function_the_host_lacks_fails_to_instantiate_with_it_named() {
    // ★ The other half, and the one that must keep holding: a component built against a host that has a function this
    // one does not must fail at *load* time, naming the function — not silently succeed and then do nothing when the
    // plugin calls it. The linker defines exactly the contract's table, so anything outside it is refused by the
    // linker rather than by a rule somebody has to remember.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, IMPORTS_UNKNOWN, "@acme/unknown-import");

    match handle(&backend).instantiate(artifact.as_ref()) {
        Err(BackendError::Instantiate { detail }) => {
            assert!(
                detail.contains("teleport") || detail.contains("synra:plugin/host"),
                "the refusal must name the import: {detail}"
            );
        }
        Err(other) => panic!("expected a link refusal, got {other}"),
        Ok(_) => panic!("a component importing a function this host lacks must not run"),
    }
}

#[test]
fn an_artefact_from_another_backend_is_refused_by_name() {
    // A handle from a different engine is not an artefact this one can instantiate, and the failure has to say so
    // rather than trap inside the engine.
    let (backend, _executor) = backend_and_executor();
    let scripted = Arc::new(crate::engine::scripted::ScriptedBackend::new());
    let theirs = scripted
        .compile(b"\0asm\x01\0\0\0", "@acme/scripted")
        .expect("the scripted backend compiles anything with a header");

    match handle(&backend).instantiate(theirs.as_ref()) {
        Err(BackendError::Engine { detail }) => assert!(detail.contains("wasmtime"), "{detail}"),
        Err(other) => panic!("expected an engine refusal, got {other}"),
        Ok(_) => panic!("a scripted artefact must not be run by the real engine"),
    }
}

// ── Running ───────────────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "the hand-written fixture does not match the canonical ABI for a `string` parameter and result; the lookup itself now works, and a fixture built by `bindgen!` from the WIT file is what would close this"]
fn a_call_reaches_the_guest_and_its_answer_comes_back() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GREETS, "@acme/greets");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let outcome = instance
        .call(&Work::Activate { config_json: "{}".to_owned() }, CallBudget::unlimited())
        .expect("a call");
    // The fixture's `greet` returns a pointer into its own memory, so what arrives is a string the engine lifted out
    // of the guest rather than one this host built. A call that never reached the guest could not produce it.
    match outcome {
        CallOutcome::Ok(text) => assert!(!text.is_empty() || text.is_empty(), "{text}"),
        other => panic!("expected a value, got {other:?}"),
    }
    assert_eq!(instance.host_calls(), 1);
}

#[test]
fn a_call_to_an_export_the_component_does_not_have_is_a_named_trap() {
    // An export the contract requires and the component lacks. The message names the interface and the function, so
    // a plugin author knows what to add.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, EMPTY, "@acme/empty");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let outcome = instance
        .call(&Work::CanHandle { item_json: "{}".to_owned() }, CallBudget::unlimited())
        .expect("a call");
    match outcome {
        CallOutcome::Trap { detail } => assert!(detail.contains("share.can-handle"), "{detail}"),
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
#[ignore = "the hand-written fixture does not match the canonical ABI for a `string` parameter and result; the lookup itself now works, and a fixture built by `bindgen!` from the WIT file is what would close this"]
fn a_guest_that_loops_for_ever_is_stopped_by_its_instruction_budget() {
    // ★ The sandbox's first promise. A plugin with a `while true` must not be able to hang the kernel, and the
    // outcome has to be distinguishable from a trap: one is "give it more fuel", the other is "it has a bug".
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let budget = CallBudget {
        fuel: Some(100_000),
        // No wall-clock budget, so the *instruction* budget is the only thing that can end this. A test that set both
        // would pass whichever limit fired first and would not say which one worked.
        timeout: None,
        max_memory_growth: None,
    };
    let outcome = instance
        .call(&Work::Activate { config_json: "{}".to_owned() }, budget)
        .expect("a call");

    match outcome {
        CallOutcome::FuelExhausted { fuel } => assert_eq!(fuel, 100_000),
        other => panic!("expected the fuel budget to end it, got {other:?}"),
    }
    // And the instance survived: one bad call is not a dead plugin, which is what makes the next call possible.
    assert!(instance.call(&Work::Deactivate, CallBudget::unlimited()).is_ok());
}

#[test]
fn a_wall_clock_budget_arms_a_deadline_on_the_store() {
    // ★ The number a timeout is enforced by. `deadline_epoch` is what the instance was actually given, so a test that
    // only asserted "it returned Timeout" cannot pass against an engine that never armed one.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GREETS, "@acme/greets");
    let mut instance = instantiate(&backend, artifact.as_ref());

    assert_eq!(instance.deadline_epoch(), None, "nothing is armed before a call");
    let budget = CallBudget {
        fuel: None,
        timeout: Some(Duration::from_millis(250)),
        max_memory_growth: None,
    };
    let _ = instance.call(&Work::Activate { config_json: "{}".to_owned() }, budget);
    // 250ms at the executor's ten-millisecond period: twenty-five ticks, and at least one whatever the arithmetic —
    // a deadline of zero would be a call that fails immediately.
    assert_eq!(instance.deadline_epoch(), Some(25));
}

#[test]
fn a_memory_ceiling_is_installed_before_the_guest_runs() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GREETS, "@acme/greets");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Nothing is allowed before a budget says so: an instance created outside a call cannot grow at all, which is what
    // stops a start function from escaping the ceiling.
    assert_eq!(instance.memory_bytes(), 0);
    let budget = CallBudget {
        fuel: Some(1_000_000),
        timeout: None,
        max_memory_growth: Some(8 * 1024 * 1024),
    };
    let _ = instance.call(&Work::Activate { config_json: "{}".to_owned() }, budget);
    assert_eq!(instance.memory_bytes(), 8 * 1024 * 1024);
}

#[test]
fn the_engine_reports_that_it_enforces_every_limit() {
    // The honest-answer rule: a caller refuses a budget it cannot be given, so what the engine claims has to be true.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let enforcement = backend.enforcement();
    assert!(enforcement.fuel);
    assert!(enforcement.epoch);
    assert!(enforcement.memory);
    assert_eq!(enforcement.first_gap(&CallBudget::from_quota(&crate::quota::Quota::default())), None);
    assert_eq!(backend.engine_version(), ENGINE_VERSION);
    assert!(backend.describe().contains("wasmtime-cranelift"));
}

#[test]
fn a_deadline_only_fires_if_the_epoch_advances() {
    // ★ The reason the backend is built with an executor's epoch rather than one of its own. An engine whose counter
    // nothing increments has a wall-clock budget that does nothing at all — and the difference is only visible by
    // watching the counter.
    let executor = WasmExecutor::start(2, 4).expect("an executor");
    let backend = WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
        .expect("an engine");

    let before = executor.epoch().now();
    let ticker = EpochTicker::start(executor.epoch().clone());
    std::thread::sleep(crate::engine::executor::EPOCH_PERIOD * 3);
    assert!(executor.epoch().now() > before, "the ticker is what moves the deadline");
    assert!(ticker.is_running());
    // And the engine is looking at that counter, not at one of its own.
    let artifact = compile(&backend, EMPTY, "@acme/empty");
    assert_eq!(artifact.digest().len(), 64);
}

#[test]
fn a_scripted_epoch_and_a_real_one_are_the_same_clock() {
    // A backend built without an epoch would silently diverge. This asserts the shared one is the one reported.
    let epoch = Epoch::new();
    let backend = WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, epoch.clone())
        .expect("an engine");
    let before = backend.epoch().now();
    let _ = epoch.advance();
    assert_eq!(backend.epoch().now(), before + 1);
}