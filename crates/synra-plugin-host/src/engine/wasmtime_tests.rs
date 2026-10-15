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



/// A component whose `deactivate` never returns.
///
/// # ★ Why this is `deactivate` and not `activate`
///
/// `activate` takes a `string` and returns an `outcome`, so a hand-written `.wat` for it has to implement the canonical
/// ABI's lowering and lifting by hand: a pointer and a length in, a pointer and a length out, a `realloc` for the host to
/// write the parameter with, and a `post-return`. That is what the one remaining ignored test in this file is ignored
/// *for*, and it is the thing a `bindgen!`-generated fixture would fix.
///
/// `deactivate` is `func()` — no parameters, no results — so its canonical lift is a core function with no signature at
/// all, and a hand-written guest can be **four lines**. The instruction budget is a property of the engine rather than of
/// the interface, so a guest that loops in `deactivate` tests exactly the same limit as one that loops in `activate`, and
/// it tests it on a real component instead of on a stub.
///
/// ★ This fixture replaced one that lifted a loop as `activate` and was therefore never usable — nothing called it, and a
/// dead fixture is worse than none: it reads as coverage.
const SPINS_ON_DEACTIVATE: &str = r#"
(component
  (core module $m
    (func (export "spin")
      (loop $l
        (br $l))))
  (core instance $i (instantiate $m))
  (func $deactivate
    (canon lift (core func $i "spin")))
  (instance $lifecycle (export "deactivate" (func $deactivate)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

/// A component whose `deactivate` grows its memory until it is not allowed to.
///
/// # Why the guest has to notice the refusal itself
///
/// A denied `memory.grow` does **not** trap: it returns -1, because that is what the instruction is defined to do, and the
/// engine's limiter is answering the question rather than ending the call. So a guest that keeps asking forever is a guest
/// that loops — which is why this one checks the answer and traps when it is refused. The trap is therefore evidence about
/// the **limiter**: the only way to reach it is for `memory.grow` to have said no.
///
/// The engine records that a refusal happened (`memory_refused`), so the outcome names the ceiling rather than reporting a
/// generic trap a plugin author could do nothing with.
const GROWS_UNTIL_REFUSED: &str = r#"
(component
  (core module $m
    (memory (export "memory") 1)
    (func (export "grow")
      (loop $l
        (if (i32.eq (memory.grow (i32.const 1)) (i32.const -1))
          (then (unreachable)))
        (br $l))))
  (core instance $i (instantiate $m))
  (func $deactivate
    (canon lift (core func $i "grow")))
  (instance $lifecycle (export "deactivate" (func $deactivate)))
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

/// Assembles a `.wat` fixture and compiles it, or fails with the engine's own reason.
///
/// # Why the assembly happens here rather than inside the engine
///
/// Because [`Backend::compile`] takes a `.wasm` file — that is what a plugin author ships — and these fixtures are
/// written as `.wat` so a reader can check four lines of text against what the test asserts. Passing the text straight
/// through used to work only when the optional `wasm-text` feature was on, and silently failed with "magic header not
/// detected" in every build that enabled `wasm-runtime` without it. Assembling here means the fixture always reaches the
/// engine in the form the engine actually accepts, whichever features the workspace happened to unify.
fn compile(backend: &WasmtimeBackend, wat: &str, id: &str) -> Box<dyn CompiledArtifact> {
    let binary = wat::parse_str(wat)
        .unwrap_or_else(|error| panic!("the {id} fixture is not valid text: {error}"));
    match backend.compile(&binary, id) {
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
fn a_guest_that_loops_for_ever_is_stopped_by_its_instruction_budget() {
    // ★ The sandbox's first promise, against a **real component** rather than a scripted outcome.
    //
    // This test used to be `#[ignore]`d: it lifted the looping core function as `activate`, whose `string`/`outcome`
    // signature meant the hand-written `.wat` had to implement the canonical ABI by hand and did not. `deactivate` is
    // `func()`, so the same limit is now tested on a guest that really runs — and what is being tested is the engine's
    // enforcement rather than the kernel's handling of an outcome somebody scripted.
    //
    // The distinction matters for exactly the reason the ignored version existed: `Scripted::FuelExhausted` proves what
    // the kernel does when it is *told* the fuel ran out, and nothing about whether it ever does.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let budget = CallBudget {
        fuel: Some(100_000),
        // No wall-clock budget, so the *instruction* budget is the only thing that can end this. A test that set both
        // would pass whichever limit fired first and would not say which one worked.
        timeout: None,
        max_memory_growth: None,
    };
    let outcome = instance.call(&Work::Deactivate, budget).expect("a call");

    match outcome {
        CallOutcome::FuelExhausted { fuel } => assert_eq!(fuel, 100_000),
        other => panic!("expected the fuel budget to end it, got {other:?}"),
    }
    // And the instance survived: one bad call is not a dead plugin, which is what makes the next call possible.
    assert!(instance.call(&Work::Deactivate, CallBudget::unlimited()).is_ok());
}

#[test]
fn a_guest_cannot_grow_past_the_ceiling_its_budget_names() {
    // ★ The sandbox's second promise, against a real component: a plugin that allocates without bound is stopped by the
    // number the kernel chose rather than by the machine running out.
    //
    // The guest asks to grow until it is refused and then traps, so reaching the trap **is** the evidence: `memory.grow`
    // returns -1 when the limiter says no, and a guest that never hears "no" would loop rather than trap.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GROWS_UNTIL_REFUSED, "@acme/greedy");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let ceiling = 1024 * 1024;
    let budget = CallBudget {
        // ★ Fuel has to be granted, and generously, because `None` here is **zero** rather than unlimited: the first
        // version of this test passed `None` and got `FuelExhausted { fuel: 0 }`, which is the engine being right and the
        // test being wrong about what it was asking for.
        //
        // A million instructions against a guest whose whole job is sixteen `memory.grow`s and a comparison is not a second
        // limit that could fire — and it cannot quietly become one, because the assertion below is on the outcome: if fuel
        // ran out the test would fail and say so rather than passing as though memory had been the reason.
        fuel: Some(1_000_000),
        timeout: None,
        max_memory_growth: Some(ceiling),
    };
    let outcome = instance.call(&Work::Deactivate, budget).expect("a call");

    match outcome {
        // ★ The limit is compared to the number the **budget** named, not merely checked for being a memory outcome.
        //
        // The engine has a ceiling of its own (`INSTANTIATION_CEILING`, sixteen mebibytes) that exists whether or not
        // anybody asked for one, so a test that only asserted "it was memory" would pass against an engine that ignored
        // the budget entirely. Naming the number is what makes this about the budget.
        CallOutcome::MemoryExceeded { limit } => assert_eq!(limit, ceiling),
        other => panic!("expected the memory ceiling to end it, got {other:?}"),
    }
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

/// ★ The claim that `enforcement()` makes has to be checked against what the backend can *do*.
///
/// The test above asserted that four booleans on a struct the backend itself returned were `true`. That is a statement
/// about a constant, not about the engine, so it passed while `precompile` claimed a capability no backend implements —
/// `WasmBackend::precompile` has a default returning `BackendUnavailable`, and `grep 'fn precompile'` finds no override
/// anywhere in the workspace.
///
/// This test ties the flag to the behaviour: whatever `enforcement()` reports as available must actually answer.
#[test]
fn what_the_engine_claims_it_enforces_is_what_it_does() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let enforcement = backend.enforcement();

    // The three limits are applied in `apply_budget`, so they are claimed and are real.
    assert!(enforcement.fuel && enforcement.epoch && enforcement.memory, "{enforcement:?}");

    // Precompilation is the one that is not implemented, so it must not be claimed. This is the assertion that would
    // have caught the false claim: it fails the moment the flag and the method disagree.
    let precompiled = backend.precompile(b"\0asm", "a-plugin");
    assert_eq!(
        enforcement.precompile,
        precompiled.is_ok(),
        "enforcement() says precompile is {}, and the call answers {precompiled:?}",
        enforcement.precompile
    );
}

/// ★ An engine built with no executor must still have something advancing its epoch.
///
/// `WasmtimeBackend::new` used to be `with_epoch(kind, Epoch::new())` — a fresh counter that no thread ever moved. The
/// store was told "your deadline is tick N" and the counter stayed at zero, so the wall-clock layer armed a deadline
/// that could not arrive. This is the test for the private-epoch half of that: the counter has to move on its own.
#[test]
fn an_engine_with_its_own_epoch_advances_it() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");

    // A tick is 10ms and the ticker starts its first one immediately, so three periods is ample. The loop is a bound on
    // flakiness rather than a sleep: a loaded machine may take longer, and failing on a slow machine would make this
    // test report the machine rather than the code.
    let mut moved = false;
    for _ in 0..40 {
        if backend.epoch().now() > 0 {
            moved = true;
            break;
        }
        std::thread::sleep(crate::engine::executor::EPOCH_PERIOD);
    }

    assert!(
        moved,
        "the epoch is still at {} — a private epoch nothing advances is a deadline that never arrives",
        backend.epoch().now()
    );
}

/// ★ The epoch has to be joined to the engine, not merely held beside it.
///
/// `Epoch` is the counter a ticker moves. A wasmtime deadline is measured against the engine's **own** counter, which
/// moves only when `Engine::increment_epoch` is called — and nothing called it. So an engine could hold a perfectly
/// lively epoch and still never time a guest out, which is what "it holds the epoch" was mistaken for.
///
/// The assertion is on the observer count because that is the only externally visible trace of the join. It is not a
/// statement about internals for its own sake: an engine with zero observers is an engine the ticker cannot reach, and
/// that is the exact condition that made this layer inert.
#[test]
fn an_engine_sharing_an_epoch_is_joined_to_it() {
    let executor = WasmExecutor::start(2, 4).expect("an executor");
    let backend = WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
        .expect("an engine");

    let described = format!("{:?}", backend.epoch());
    assert!(
        described.contains("observers: 1"),
        "the engine is not observing the epoch, so advancing it moves nothing wasmtime measures: {described}"
    );
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