//! Every open link the kernel knows about, and what it reports when one changes.
//!
//! # Why this is a directory and not a file
//!
//! Because what the registry *reports* and *refuses* is separable from the registry itself. The two enums are the
//! vocabulary an observer and a caller use; the registry is the map they describe. In one file they were the first
//! hundred lines a reader had to get past before reaching the behaviour.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `event` | what the registry reports when a session changes |
//! | `error` | why an operation on the registry was refused |
//! | `table` | the registry itself, and the transitions it permits |

mod event;
mod error;
mod table;

pub use error::RegistryError;
pub use event::RegistryEvent;
pub use table::SessionRegistry;
