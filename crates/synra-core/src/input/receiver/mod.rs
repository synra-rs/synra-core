use parking_lot::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use synra_platform::pointer::Factory;

use super::Policy;

mod model;
mod release;
mod service;
mod state;

pub use model::{Phase, Snapshot};

/// One exclusive desktop pointer owner, shared by incoming links and host decisions.
pub struct Receiver {
    policy: Arc<dyn Policy>,
    factory: Arc<Factory>,
    state: Mutex<Option<Snapshot>>,
    pointer_lease: Mutex<()>,
    publication: Mutex<Option<Snapshot>>,
    stopping: AtomicBool,
    notify: Arc<dyn Fn(Option<Snapshot>) + Send + Sync>,
}
