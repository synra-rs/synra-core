//! The kernel's event bus: one publish point, one queue per subscriber.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: what a subscriber *is* and what it is told, the queue that holds its
//! events and reports the gaps, the bus that publishes into every queue, and the tracker that decides what a
//! sequence number meant. In one file the gap arithmetic — the part that decides whether an interface has
//! silently missed an event — sat inside a nine-hundred-line `impl`.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `subscription` | the subscriber's identity, its report, and what it reads |
//! | `queue` | one subscriber's queue, and what it says about itself |
//! | `fanout` | the bus, and the one lock it publishes under |
//! | `sequence` | what a subscriber decided about a sequence number, and the tracker |

mod subscription;
mod queue;
mod fanout;
mod sequence;

#[cfg(test)]
mod tests;

pub use fanout::EventBus;
pub use sequence::{Judgement, SequenceTracker};
pub use subscription::{Delivery, SUBSCRIBER_QUEUE_CAPACITY, SubscriberId, SubscriberReport};
