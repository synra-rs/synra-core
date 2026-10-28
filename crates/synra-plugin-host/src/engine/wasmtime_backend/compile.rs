//! Compiler stack ownership, independent of a desktop caller's native stack.

use super::BackendError;
use parking_lot::Mutex;
use wasmtime::{Engine, component::Component};

// Cranelift compiling a real SDK component overflowed Windows' 1 MiB main stack.
// This is host compiler space; the guest's separate Wasm stack limit is unchanged.
const STACK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub(super) struct Compiler {
    // Shared by backend clones: at most one compilation worker per engine. There is
    // no job queue or owned input copy; the synchronous caller lends bounded bytes.
    admission: Mutex<()>,
}

impl Compiler {
    pub(super) fn compile(&self, engine: &Engine, wasm: &[u8]) -> Result<Component, BackendError> {
        let admission = self.admission.lock();
        let result = std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("synra-wasm-compile".to_owned())
                .stack_size(STACK_BYTES)
                .spawn_scoped(scope, || {
                    Component::new(engine, wasm).map_err(|error| BackendError::Compile {
                        detail: format!("{error:#}"),
                    })
                })
                .map_err(|error| BackendError::Engine {
                    detail: format!("compiler worker could not start: {error}"),
                })?;
            worker.join().map_err(|_| BackendError::Compile {
                detail: "compiler worker panicked".to_owned(),
            })?
        });
        drop(admission);
        result
    }
}
