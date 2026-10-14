//! The states a plugin moves through, and the transitions each one permits.
//!
//! # Why this is a directory and not a file
//!
//! Because the state machine and the record of what happened to it are different subjects. `State`,
//! `Transition` and `TransitionError` decide *whether* a move is allowed; `Lifecycle` remembers what a
//! particular plugin did; `StopRecord` is what the health history keeps. In one file the enum definitions sat
//! above a three-hundred-line `impl`, and a reader changing a rule had to scroll past the history to find it.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `state` | where a plugin is in its life |
//! | `transition` | what may be done, and why a move was refused |
//! | `machine` | one plugin's lifecycle, and the moves it permits |
//! | `record` | how a plugin was stopped, and how many stops make a version unstable |

mod state;
mod transition;
mod machine;
mod record;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use machine::Lifecycle;
pub use record::{StopRecord, UNSTABLE_THRESHOLD};
pub use state::State;
pub use transition::{Transition, TransitionError};
