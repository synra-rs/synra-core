//! Host-owned execution identity and causal limits, never supplied by a guest.

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
use synra_protocol::{PluginId, RequestId};

pub(crate) struct Execution {
    pub runtime: RequestId,
    pub generation: RequestId,
    pub plugin: PluginId,
    pub version: String,
    pub manifest_digest: String,
}

#[derive(Clone)]
pub(super) struct Cause {
    pub runtime: RequestId,
    pub depth: u8,
    emitted: Arc<AtomicU32>,
    delivered: Arc<AtomicU32>,
}

impl Cause {
    pub(super) fn root(runtime: RequestId) -> Self {
        Self {
            runtime,
            depth: 0,
            emitted: Arc::new(AtomicU32::new(0)),
            delivered: Arc::new(AtomicU32::new(0)),
        }
    }
    pub(super) fn next(&self) -> Option<Self> {
        if self.depth >= 8 || !take(&self.emitted) {
            return None;
        }
        Some(Self {
            depth: self.depth + 1,
            ..self.clone()
        })
    }
    pub(super) fn take_delivery(&self) -> bool {
        take(&self.delivered)
    }
}

fn take(counter: &AtomicU32) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    while current < 32 {
        match counter.compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(updated) => current = updated,
        }
    }
    false
}

thread_local! {
    static EXECUTION: RefCell<Option<Arc<Execution>>> = const { RefCell::new(None) };
    static CAUSE: RefCell<Option<Cause>> = const { RefCell::new(None) };
}

pub(crate) fn current() -> Option<Arc<Execution>> {
    EXECUTION.with(|slot| slot.borrow().clone())
}
pub(super) fn cause(runtime: RequestId) -> Cause {
    CAUSE
        .with(|slot| {
            slot.borrow()
                .as_ref()
                .filter(|cause| cause.runtime == runtime)
                .cloned()
        })
        .unwrap_or_else(|| Cause::root(runtime))
}

pub(crate) struct ExecutionScope(Option<Arc<Execution>>);
pub(crate) fn enter(execution: Arc<Execution>) -> ExecutionScope {
    ExecutionScope(EXECUTION.with(|slot| slot.replace(Some(execution))))
}
impl Drop for ExecutionScope {
    fn drop(&mut self) {
        EXECUTION.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

pub(super) struct CauseScope(Option<Cause>);
pub(super) fn enter_cause(cause: Cause) -> CauseScope {
    CauseScope(CAUSE.with(|slot| slot.replace(Some(cause))))
}
impl Drop for CauseScope {
    fn drop(&mut self) {
        CAUSE.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}
