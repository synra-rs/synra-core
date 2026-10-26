//! Real component compilation, calls, interruption and resource limits.
//!
//! These tests run with wasm-runtime. The dev-only WAT assembler keeps text fixtures independent
//! of the optional wasm-text feature; typed host imports and result codecs come from production WIT.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::engine::executor::{Epoch, EpochTicker, WasmExecutor};
use crate::engine::types::{Backend, WasmBackend};

/// A backend sharing an executor's epoch, as a running kernel builds it.
pub(super) fn backend_and_executor() -> (Arc<WasmtimeBackend>, WasmExecutor) {
    let executor = WasmExecutor::start(2, 4).expect("an executor");
    let backend =
        WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
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

/// A component whose `deactivate` returns at once.
const STOPS: &str = r#"
(component
  (core module $m
    (func (export "stop")))
  (core instance $i (instantiate $m))
  (func $deactivate
    (canon lift (core func $i "stop")))
  (instance $lifecycle (export "deactivate" (func $deactivate)))
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
)
"#;

/// Spins without parameters or results so the instruction-limit test isolates execution budgeting.
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

/// Returns bytes owned by the guest, rather than an answer synthesized by the host.
/// Canonical lift receives the input string as pointer/length and returns an i32 pointing to the
/// result string's pointer/length pair in guest memory. It does not take an extra result parameter.
pub(super) const ANSWERS: &str = r#"
(component
  (core module $m
    (memory (export "memory") 1)
    (data (i32.const 1024) "hello from the plugin")
    (global $next (mut i32) (i32.const 4096))
    (func (export "realloc") (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32) (result i32)
      (local $at i32)
      (local.set $at (global.get $next))
      (global.set $next (i32.add (local.get $at) (local.get $new-size)))
      (local.get $at))
    (func (export "answer") (param $ptr i32) (param $len i32) (result i32)
      (i32.store (i32.const 2048) (i32.const 1024))
      (i32.store (i32.const 2052) (i32.const 21))
      (i32.const 2048)))
  (core instance $i (instantiate $m))
  (func $can_handle (param "item-json" string) (result string)
    (canon lift (core func $i "answer")
      (memory (core memory $i "memory"))
      (realloc (core func $i "realloc"))))
  (instance $share (export "can-handle" (func $can_handle)))
  (instance $lifecycle)
  (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle))
  (export "synra:plugin/share@1.0.0" (instance $share))
)
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
pub(super) fn compile(backend: &WasmtimeBackend, wat: &str, id: &str) -> Box<dyn CompiledArtifact> {
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
pub(super) fn instantiate(
    backend: &Arc<WasmtimeBackend>,
    artifact: &dyn CompiledArtifact,
) -> Box<dyn PluginInstance> {
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
fn an_artifact_larger_than_the_ceiling_is_refused_before_the_engine_sees_it() {
    // """ + S + """ The limit the host did not have.
    //
    // The CLI refuses a `.wasm` over 16 MiB and the registry refuses a packument over 8 MiB, and `compile` checked only
    // whether the bytes were empty — so anything arriving by another road went straight into the engine, whose parser is not
    // a resource limiter.
    //
    // """ + S + """ And what makes this test about *our* refusal rather than wasmtime's.
    //
    // A megabyte of zeroes is not a component, so the engine would refuse it too, with a parse error. The assertion is on the
    // message: it names both numbers, which only this layer can produce.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let oversized = vec![0u8; super::super::MAX_COMPONENT_BYTES + 1];

    match backend.compile(&oversized, "@acme/huge") {
        Err(BackendError::Compile { detail }) => {
            assert!(
                detail.contains("16777217"),
                "it names the size it was given: {detail}"
            );
            assert!(
                detail.contains("16777216"),
                "and the largest it accepts: {detail}"
            );
        }
        // A compiled artifact has no `Debug`, so the arm reports that it succeeded rather than showing one.
        Ok(_) => panic!("a 16 MiB artifact was compiled"),
        Err(other) => panic!("expected a size refusal, got {other}"),
    }
}

#[test]
fn an_empty_artifact_is_refused_before_the_engine_sees_it() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    assert!(matches!(
        backend.compile(b"", "p"),
        Err(BackendError::Compile { .. })
    ));
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
    assert_eq!(
        artifact.digest().len(),
        64,
        "a digest is what a cache key is built from"
    );
    assert!(
        artifact
            .digest()
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
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
    assert_eq!(concrete.imports(), ["synra:plugin/host#env-sdk-version"]);
}

#[test]
fn unexpected_resources_in_the_host_interface_are_not_dropped_from_import_checks() {
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).unwrap();
    let artifact = compile(
        &backend,
        r#"(component
      (import "synra:plugin/host@1.0.0" (instance
        (export "unexpected" (type (sub resource)))))
      (instance $lifecycle)
      (export "synra:plugin/lifecycle@1.0.0" (instance $lifecycle)))"#,
        "@acme/resource-import",
    );
    assert_eq!(artifact.imports(), ["synra:plugin/host@1.0.0#unexpected"]);
    let grants = synra_capability::CapabilitySet::new();
    assert_eq!(
        crate::host_surface::undeclared_imports(artifact.imports(), &grants),
        artifact.imports()
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
fn a_call_reaches_the_guest_and_its_answer_comes_back() {
    // ★ The one test that proves the whole path: a call goes in, the guest runs, and bytes the **host never built** come
    // back out. Everything else in this file tests a part of it — the lookup, the instantiation, the limits, the traps.
    //
    // ★ And its assertion used to be a tautology.
    //
    // The ignored version ended with `assert!(!text.is_empty() || text.is_empty())`, which is true for every string there
    // is — so even with a working fixture it would have proved nothing about what came back. It now names the answer, and
    // the answer is twenty-one characters the guest wrote into its own memory.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, ANSWERS, "@acme/answers");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let outcome = instance
        .call(
            &Work::CanHandle {
                item_json: "{\"mime\":\"text/plain\"}".to_owned(),
            },
            CallBudget::unlimited(),
        )
        .expect("a call");

    match outcome {
        CallOutcome::Ok(text) => assert_eq!(text, "hello from the plugin"),
        other => panic!("expected the guest's own string, got {other:?}"),
    }
    assert_eq!(
        instance.host_calls(),
        0,
        "the guest called nothing; the string is its own"
    );
    // ★ The reading the plugin group's `plugin_fuel_consumed` histogram is built from: the store is set to the budget
    // before the call and the remainder is read after, so a guest that ran spent something. `unlimited` gives `u64::MAX`,
    // which is why the assertion is "more than zero" rather than a number only this fixture could name.
    assert!(
        instance.last_fuel_consumed().is_some_and(|fuel| fuel > 0),
        "a call that reached the guest reports the fuel it spent"
    );
}

#[test]
fn a_call_to_an_export_the_component_does_not_have_is_a_named_trap() {
    // An export the contract requires and the component lacks. The message names the interface and the function, so
    // a plugin author knows what to add.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, EMPTY, "@acme/empty");
    let mut instance = instantiate(&backend, artifact.as_ref());

    let outcome = instance
        .call(
            &Work::CanHandle {
                item_json: "{}".to_owned(),
            },
            CallBudget::unlimited(),
        )
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
    // ★ Exactly the budget: a guest stopped by fuel has a zero remainder, so the pair-around-the-call arithmetic is
    // `granted - 0`. Asserted before the second call, which would replace the reading with its own.
    assert_eq!(
        instance.last_fuel_consumed(),
        Some(100_000),
        "an exhausted budget reports what it was given"
    );
    // And the instance survived: one bad call is not a dead plugin, which is what makes the next call possible.
    assert!(
        instance
            .call(&Work::Deactivate, CallBudget::unlimited())
            .is_ok()
    );
}

#[test]
fn a_budget_that_names_no_ceiling_is_still_bounded() {
    // """ + S + """ The one layer where `None` must **not** mean "no limit", and the reason is worth a test rather than a
    // comment.
    //
    // The other two layers read `None` as "the caller named no limit for this layer", and rounds 95 to 97 fixed the engine
    // to honour that. Memory is different: a budget that names no ceiling is held to `INSTANTIATION_CEILING`, the sixteen
    // mebibytes an instance is created with. That is deliberate — `execute_budget()` in `synra-core` names no memory
    // ceiling, so an action is bounded by time alone, and the instantiation ceiling is the last-resort cap that stops a
    // hostile `execute` from eating the machine.
    //
    // """ + S + """ Which is exactly why it is pinned.
    //
    // The inconsistency is visible, and the obvious "fix" — making `None` clear the ceiling, as the other two layers now do
    // — would **remove the sandbox's last resort**. A future reader who notices the asymmetry should find this test and the
    // number in it rather than a commit that quietly uncapped memory.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, GROWS_UNTIL_REFUSED, "@acme/greedy");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // No ceiling named, and enough instructions that the guest reaches the wall rather than its budget.
    let outcome = instance
        .call(
            &Work::Deactivate,
            CallBudget {
                fuel: Some(1_000_000),
                timeout: None,
                max_memory_growth: None,
            },
        )
        .expect("a call");

    match outcome {
        // """ + S + """ And the number is the ceiling **in force**, not the budget's absence.
        //
        // `classify` reported `budget.max_memory_growth.unwrap_or(0)` — so this outcome used to name a limit of **zero** when
        // the wall the guest hit was sixteen mebibytes. That is the number a plugin author would go and change.
        // ★ Asserted against the constant rather than the number, which is the difference between a test that
        // checks the ceiling is reported and one that checks the arithmetic somebody typed matches theirs.
        CallOutcome::MemoryExceeded { limit } => assert_eq!(
            limit, INSTANTIATION_CEILING as u64,
            "an unnamed ceiling is the instantiation ceiling, and the outcome must name it"
        ),
        other => panic!(
            "a guest that grows without bound must hit the instantiation ceiling, got {other:?}"
        ),
    }
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
fn a_call_that_asks_for_no_fuel_is_given_fuel_rather_than_left_at_zero() {
    // """ + S + """ "No instruction limit" is the one budget the engine cannot express by doing nothing.
    //
    // Every store is built with `consume_fuel(true)` and starts at **zero**. Setting fuel only when the budget names an
    // amount left a call that named none with nothing to spend, so a guest trapped at once with `FuelExhausted { fuel: 0 }`
    // — a plugin reported as out of instructions when its budget said there was no limit. A reused instance was worse rather
    // than better: it inherited the previous call's remainder, which can also be zero.
    //
    // """ + S + """ On a fresh instance, and about the tank rather than about reuse.
    //
    // The first version of this test called the same instance twice after draining it, and what it found was a different
    // bug entirely: a **trapped** component instance cannot be entered again, so reuse after a stop is not something the
    // engine offers. Discarding such an instance is `PluginSet`'s job — `a_plugin_that_exhausts_its_budget_is_not_broken_afterwards`
    // in `synra-core` is where that lives — and asserting it here would have been asserting a contract this layer never
    // made.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Unlimited instructions, bounded by the clock so the test cannot hang. Both facts matter: without the fuel the guest
    // stops before it starts, and without the clock it never stops.
    let started = std::time::Instant::now();
    let outcome = instance
        .call(
            &Work::Deactivate,
            CallBudget {
                fuel: None,
                timeout: Some(Duration::from_millis(250)),
                max_memory_growth: None,
            },
        )
        .expect("a call");

    match outcome {
        CallOutcome::Timeout { .. } => {}
        other => {
            panic!("a budget with no instruction limit should run until its clock, got {other:?}")
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "and it should stop near that clock rather than running on"
    );
}

#[test]
fn a_real_guest_that_loops_is_stopped_by_the_wall_clock_not_by_zero() {
    // """ + S + """ The other half of the round-95 fix, and the half nothing covered.
    //
    // Disarming the deadline for `timeout: None` is only correct if `timeout: Some(_)` still **arms** one and still stops a
    // real guest. The test beside this one proves the disarming; this proves the arming, with a guest that genuinely never
    // returns, so an error in either branch cannot hide behind the other.
    //
    // """ + S + """ And it asserts the **duration in the outcome**, which is what `after: 0ns` was.
    //
    // That value was the signature of the bug: a call interrupted by the instantiation deadline it never asked for reported
    // a timeout of zero, because the budget had no duration to name. A real wall-clock stop has a duration to name, and it
    // is the one the budget asked for.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Enough fuel to run for far longer than the clock allows, so the layer that stops this is the wall clock rather than
    // the instruction budget — otherwise the test would pass for the wrong reason.
    let budget = CallBudget {
        fuel: Some(1_000_000_000),
        timeout: Some(Duration::from_millis(250)),
        max_memory_growth: None,
    };

    let started = std::time::Instant::now();
    let outcome = instance.call(&Work::Deactivate, budget).expect("a call");
    let elapsed = started.elapsed();

    match outcome {
        CallOutcome::Timeout { after } => assert_eq!(
            after,
            Duration::from_millis(250),
            "the outcome names the budget's duration, not zero"
        ),
        other => panic!("a real infinite loop must be stopped by its wall clock, got {other:?}"),
    }
    // And it stopped near the deadline rather than running until its fuel ran out, which is what makes the assertion above
    // about the clock rather than about a coincidence.
    assert!(
        elapsed < Duration::from_secs(30),
        "it ran for {elapsed:?}, so something other than the 250ms budget stopped it"
    );
}

#[test]
fn a_budget_with_no_time_limit_leaves_no_deadline_armed() {
    // Advance beyond the constructor's finite deadline before making an unlimited call.
    // Retaining startup's deadline would interrupt the call deterministically.
    let (backend, executor) = backend_and_executor();
    let artifact = compile(&backend, STOPS, "@acme/stops");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // The epoch is already past the deadline instantiation armed.
    let ticks = ticks_for(INSTANTIATION_TIMEOUT);
    for _ in 0..=ticks {
        executor.epoch().advance();
    }

    let outcome = instance
        .call(
            &Work::Deactivate,
            CallBudget {
                fuel: None,
                timeout: None,
                max_memory_growth: None,
            },
        )
        .expect("a call");

    assert!(
        !matches!(outcome, CallOutcome::Timeout { .. }),
        "a budget with no wall clock was timed out anyway: {outcome:?}"
    );
    // And the observable state agrees: nothing is armed, rather than a tick that cannot be told from a real deadline.
    assert_eq!(instance.deadline_epoch(), None);
}

#[test]
fn a_wall_clock_budget_arms_a_deadline_on_the_store() {
    // ★ The number a timeout is enforced by. `deadline_epoch` is what the instance was actually given, so a test that
    // only asserted "it returned Timeout" cannot pass against an engine that never armed one.
    // ★ The fixture is the looping one, so the call this arms a deadline for is a call that genuinely runs — and keeps
    // running until the deadline stops it. The fixture this test used to use had a canonical-ABI bug, so its call trapped
    // immediately and the deadline was asserted around a trap rather than around work.
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    assert_eq!(
        instance.deadline_epoch(),
        None,
        "no call deadline has been recorded before a call"
    );
    let budget = CallBudget {
        fuel: None,
        timeout: Some(Duration::from_millis(250)),
        max_memory_growth: None,
    };
    let _ = instance.call(&Work::Deactivate, budget);
    // 250ms at the executor's ten-millisecond period: twenty-five ticks, and at least one whatever the arithmetic —
    // a deadline of zero would be a call that fails immediately.
    assert_eq!(instance.deadline_epoch(), Some(25));
}

#[test]
fn a_memory_ceiling_is_installed_before_the_guest_runs() {
    let (backend, _executor) = backend_and_executor();
    let artifact = compile(&backend, SPINS_ON_DEACTIVATE, "@acme/spins");
    let mut instance = instantiate(&backend, artifact.as_ref());

    // Nothing is allowed before a budget says so: an instance created outside a call cannot grow at all, which is what
    // stops a start function from escaping the ceiling.
    assert_eq!(instance.memory_bytes(), 0);
    let budget = CallBudget {
        fuel: Some(1_000_000),
        timeout: None,
        max_memory_growth: Some(8 * 1024 * 1024),
    };
    let _ = instance.call(&Work::Deactivate, budget);
    assert_eq!(instance.memory_bytes(), 8 * 1024 * 1024);
}

#[test]
fn a_host_on_this_engine_may_start_because_it_can_enforce_everything() {
    // ★ The production caller `first_gap` never had.
    //
    // The design writes this layer's safety argument as *"a backend that cannot enforce a limit a caller asks for says so, and
    // the caller refuses rather than running third-party code with a bound it does not have"* — and until now the only caller
    // was a test. This is what the daemon and the shell now call before loading any plugin.
    let backend = crate::Backend::new(std::sync::Arc::new(
        WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine"),
    ));

    assert_eq!(
        crate::engine::check_enforceable(&backend, &crate::quota::Quota::default()),
        Ok(()),
        "the wasmtime engine and the default quota agree"
    );
}

#[test]
fn a_host_on_an_engine_that_enforces_nothing_is_refused_and_told_which_limit() {
    // ★ The other half, and the half that makes the check a check: an engine that cannot bound what it runs must not be
    // started on, and the refusal names the **first** limit rather than saying "unsupported".
    //
    // The scripted backend is what makes this testable at all: it honestly reports that it has no engine, which is exactly
    // the state a future lightweight backend would be in. It is a test double, so no production path reaches it — which is
    // why the check lives where a kernel chooses its engine rather than on every call.
    let backend = crate::Backend::new(std::sync::Arc::new(crate::engine::ScriptedBackend::new()));

    match crate::engine::check_enforceable(&backend, &crate::quota::Quota::default()) {
        Err(BackendError::CannotEnforce { missing }) => {
            assert_eq!(
                missing, "an instruction budget",
                "the first limit the defaults ask for"
            );
        }
        other => panic!("an engine that enforces nothing must be refused, got {other:?}"),
    }
}

#[test]
fn the_engine_reports_that_it_enforces_every_limit() {
    // The honest-answer rule: a caller refuses a budget it cannot be given, so what the engine claims has to be true.
    let backend = WasmtimeBackend::new(BackendKind::WasmtimeCranelift).expect("an engine");
    let enforcement = backend.enforcement();
    assert!(enforcement.fuel);
    assert!(enforcement.epoch);
    assert!(enforcement.memory);
    assert_eq!(
        enforcement.first_gap(&CallBudget::from_quota(&crate::quota::Quota::default())),
        None
    );
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
    assert!(
        enforcement.fuel && enforcement.epoch && enforcement.memory,
        "{enforcement:?}"
    );

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
    let backend =
        WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
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
    let backend =
        WasmtimeBackend::with_epoch(BackendKind::WasmtimeCranelift, executor.epoch().clone())
            .expect("an engine");

    let before = executor.epoch().now();
    let ticker = EpochTicker::start(executor.epoch().clone());
    std::thread::sleep(crate::engine::executor::EPOCH_PERIOD * 3);
    assert!(
        executor.epoch().now() > before,
        "the ticker is what moves the deadline"
    );
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
