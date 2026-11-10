//! The instance pool's tests.

use super::*;

use core::time::Duration;

fn stateless(limit: u32) -> InstancePool {
    InstancePool::new(InstancePolicy::Stateless, limit)
}

fn stateful(limit: u32) -> InstancePool {
    InstancePool::new(InstancePolicy::Stateful, limit)
}

mod stateless;
mod stateful;
mod accounting;
