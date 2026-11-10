//! Event bus delivery, overflow and sequence tracking.

use super::EventBus;

/// An event, which the bus clones per subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tick(u64);

fn bus() -> EventBus<Tick> {
    EventBus::new()
}

mod sequence;
mod subscribers;
mod overflow;
mod tracking;
