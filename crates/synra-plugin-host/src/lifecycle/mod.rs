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
//! | `pipeline` | the whole thirteen states: install, run, fault, remove |
//! | `record` | how a plugin was stopped, and how many stops make a version unstable |
//!
//! # Two machines, and which one a caller wants
//!
//! [`PluginSlot`] is the thirteen states of the design document, from "in a registry" to "gone". [`Lifecycle`] is the
//! seven states a plugin that is **on this device** moves through, and it is what a slot holds once it is installed.
//!
//! The split is deliberate rather than a missing merge: the states before installation hold things the later ones do
//! not — a source, a partial download, a verification report — and one enum holding both would be thirteen variants
//! whose payloads are mostly irrelevant to whoever is reading, with "except before installation" in every method.
//! [`PluginSlot::lifecycle`] is the conversion, and it is `None` exactly while there is nothing on this device.

mod state;
mod transition;
mod machine;
mod pipeline;
mod record;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use machine::Lifecycle;
pub use pipeline::{
    Consent, FailStage, Failed, InstallSource, Move, MoveError, PluginSlot, Progress, Resolved, Verified,
    WEAR_OUT_AFTER,
};
pub use record::{StopRecord, UNSTABLE_THRESHOLD};
pub use state::State;
pub use transition::{Transition, TransitionError};
