//! The pool of Wasm instances a plugin is called through.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: how an instance is turned over, what a pool refuses, what it knows about
//! one instance, and the pool itself. In one file the three-hundred-line `impl InstancePool` sat below two hundred
//! lines of type definitions, so a reader changing a recycling rule had to scroll past everything it affects.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `policy` | when an instance is reused, recycled or evicted, and why a pool refuses |
//! | `record` | what the pool knows about one instance |
//! | `instance` | the pool itself, and its report |

mod policy;
mod record;
mod instance;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use instance::{InstancePool, PoolReport};
pub use policy::{InstancePolicy, PoolRefusal};
pub use record::{IDLE_EVICT_AFTER, InstanceRecord, RECYCLE_AFTER_CALLS};
