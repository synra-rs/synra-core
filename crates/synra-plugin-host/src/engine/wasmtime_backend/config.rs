//! Wasmtime resource and compilation policy.

use crate::engine::types::BackendKind;
use std::time::Duration;
use wasmtime::{Config, OptLevel};

/// How much host stack a wasm frame may use, in bytes.
const MAX_WASM_STACK: usize = 512 * 1024;

/// How much address space is reserved per linear memory.
///
/// Reserved rather than committed: the reservation costs nothing until it is touched, and making it explicit stops the
/// engine from deciding on its own how much address space a plugin's memory may claim.
const MEMORY_RESERVATION: u64 = 64 * 1024 * 1024;

/// How much a memory may grow by in one step before the engine re-reserves.
const MEMORY_RESERVATION_FOR_GROWTH: u64 = 2 * 1024 * 1024;

/// The memory ceiling an instance gets before a call replaces it with the plugin's own quota.
///
/// Sixteen mebibytes, and the number is not a budget: it is what a component's own declared minimum has to fit inside
/// for the instance to be creatable at all. A store that started at zero could not instantiate a module that declares
/// even one page — a plugin that never runs, rather than a plugin that cannot grow. What a *call* may reach is the
/// budget's, which is applied before the guest runs and is the number a hostile allocation meets.
pub(super) const INSTANTIATION_CEILING: usize = 16 * 1024 * 1024;

/// Finite fuel for component constructors, before a per-call budget is installed.
pub(super) const INSTANTIATION_FUEL: u64 = 1_000_000;

/// Startup deadline covers linker setup and component constructors before per-call limits apply.
pub(super) const INSTANTIATION_TIMEOUT: Duration = Duration::from_secs(1);

/// Ticks that will not be reached, for a call whose budget names no wall clock.
///
/// ★ Why not `u64::MAX`, which is the obvious way to say "no deadline".
///
/// Because wasmtime **adds** the deadline to the current epoch, and `u64::MAX` overflows that addition — inside the
/// library, as a panic: `attempt to add with overflow` in `wasmtime/src/runtime/store.rs`. The disarm value therefore has
/// to leave room for the counter, which is the sort of thing only running it teaches.
///
/// At the executor's ten-millisecond period this is about three hundred and fifty years, so it is unreachable by any run
/// of any program, and the arithmetic cannot overflow.
pub(super) const NO_DEADLINE_TICKS: u64 = 1 << 40;

/// The configuration the security baseline requires.
///
/// Every option here is one that decides what a guest may cost the host.
#[must_use]
pub(crate) fn engine_config(kind: BackendKind) -> Config {
    let mut config = Config::new();

    // ── The component model, which is what the contract is written in ──
    config.wasm_component_model(true);

    // ── Interruption: both mechanisms, because they catch different things ──
    //
    // Fuel is the instruction budget: a loop in pure arithmetic is stopped by it, deterministically. It does **not**
    // stop a guest blocked in a host call; neither can epochs. Host IO needs its own deadline and cancellation.
    // Epoch interruption independently limits elapsed time while Wasm instructions execute.
    config.consume_fuel(true);
    config.epoch_interruption(true);

    // ── Resources ──
    config.max_wasm_stack(MAX_WASM_STACK);
    config.memory_reservation(MEMORY_RESERVATION);
    config.memory_reservation_for_growth(MEMORY_RESERVATION_FOR_GROWTH);
    // No dense image: the copy it enables is what a large reservation would otherwise pay for on every instantiation.
    config.memory_guaranteed_dense_image_size(0);

    // ── Compilation ──
    //
    // Winch is the baseline compiler: quicker to produce code, slower to run it. That is the trade a phone makes,
    // where the build happens while a user waits and the run happens once.
    config.cranelift_opt_level(match kind {
        BackendKind::WasmtimeWinch => OptLevel::None,
        _ => OptLevel::Speed,
    });

    // ── Diagnostics that cost every call ──
    //
    // A backtrace is built when a trap happens, which is the moment an attacker would most like to be expensive. The
    // kernel's log records that a trap occurred and which plugin it was; a per-frame backtrace is a debugging aid that
    // is turned on deliberately.
    config.wasm_backtrace(false);

    // ★ Unwind information is deliberately **not** turned off, and it is the one baseline option the engine refuses to
    // let a host disable on Windows: the platform's own exception handling needs it. A build that turned it off would
    // fail right here, with a message naming the option — a better outcome than one that built and then crashed in a
    // way nobody could read.
    config
}
