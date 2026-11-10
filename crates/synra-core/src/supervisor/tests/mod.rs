use std::sync::Arc;

use super::{Supervisor, TaskId};

mod cancellation;
mod registration;
mod restart;
mod runner;
mod shutdown;

const NOW: i64 = 1_000;

fn supervisor() -> Arc<Supervisor> {
    Arc::new(Supervisor::new(NOW))
}

fn id(name: &str) -> TaskId {
    TaskId::new(name)
}
