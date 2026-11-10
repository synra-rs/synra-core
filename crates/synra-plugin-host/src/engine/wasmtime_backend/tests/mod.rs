//! Real component compilation, calls, interruption and resource limits.
//!
//! These tests run with wasm-runtime. The dev-only WAT assembler keeps text fixtures independent
//! of the optional wasm-text feature; typed host imports and result codecs come from production WIT.

use std::sync::Arc;
use std::time::Duration;

use super::config::{INSTANTIATION_CEILING, INSTANTIATION_TIMEOUT};
use super::{ENGINE_VERSION, EngineArtifact, WasmtimeBackend};
use crate::engine::executor::{Epoch, EpochTicker, WasmExecutor, next_tick, ticks_for};
use crate::engine::types::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, PluginInstance,
    WasmBackend, Work,
};

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

mod calls;
mod compilation;
mod enforcement;
mod epoch;
mod fuel;
mod memory;
