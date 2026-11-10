//! Shared admission and delayed child reaping for desktop commands.

use std::process::Child;
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};

use parking_lot::Mutex;

use crate::PlatformError;

pub(super) struct Gate {
    pub(super) active: AtomicUsize,
    pub(super) retired: AtomicUsize,
    limit: usize,
    unreaped: Mutex<Vec<(Child, Arc<Lease>)>>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unreaped = self.unreaped.lock().len();
        formatter
            .debug_struct("CommandGate")
            .field("active", &self.active.load(Ordering::Acquire))
            .field("retired", &self.retired.load(Ordering::Acquire))
            .field("limit", &self.limit)
            .field("unreaped", &unreaped)
            .finish()
    }
}

impl Gate {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            retired: AtomicUsize::new(0),
            limit,
            unreaped: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn acquire(self: &Arc<Self>) -> Result<Arc<Lease>, PlatformError> {
        self.reap();
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return Err(PlatformError::RunnerBusy { limit: self.limit });
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => active = current,
            }
        }
        Ok(Arc::new(Lease {
            gate: Arc::clone(self),
            cancelled: AtomicBool::new(false),
            retired: AtomicBool::new(false),
        }))
    }

    pub(super) fn retain(&self, child: Child, lease: &Arc<Lease>) {
        lease.retire();
        self.unreaped.lock().push((child, Arc::clone(lease)));
    }

    pub(super) fn reap(&self) {
        // Never hold the admission lock during an OS call or while dropping a job lease.
        let children = std::mem::take(&mut *self.unreaped.lock());
        let pending: Vec<_> = children
            .into_iter()
            .filter_map(|(mut child, lease)| {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    None
                } else {
                    Some((child, lease))
                }
            })
            .collect();
        if !pending.is_empty() {
            self.unreaped.lock().extend(pending);
        }
    }
}

#[derive(Debug)]
pub(super) struct Lease {
    pub(super) gate: Arc<Gate>,
    pub(super) cancelled: AtomicBool,
    retired: AtomicBool,
}

impl Lease {
    pub(super) fn retire(&self) {
        if !self.retired.swap(true, Ordering::AcqRel) {
            self.gate.retired.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.retired.load(Ordering::Acquire) {
            self.gate.retired.fetch_sub(1, Ordering::AcqRel);
        }
        self.gate.active.fetch_sub(1, Ordering::AcqRel);
    }
}


