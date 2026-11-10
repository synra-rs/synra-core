//! The full lifecycle: thirteen states, and what each move out of one has to carry.
//!
//! # Why this is a second machine rather than a bigger [`Lifecycle`](super::Lifecycle)
//!
//! Because the two answer different questions, and the answer to one of them is *"nothing has happened yet"*.
//! [`Lifecycle`](super::Lifecycle) is about a plugin that is **on this device**: it has a version, a manifest digest,
//! grants and possibly a running instance. The states before `Installed` are about a plugin that is not on this device
//! at all — being resolved, downloaded and checked — and each of them holds something the later states do not: a
//! source, a partial download, a verification report.
//!
//! One enum holding both would be thirteen variants whose payloads are mostly irrelevant to whoever is reading, and
//! every method would have to say "except before installation" somewhere. Two types with one conversion between them
//! says the same thing in a way a reader can check.
//!
//! # The rule the design document is emphatic about
//!
//! **`Failed` is a state, not a log line.** A pipeline that returns to `Available` on failure and writes a note has
//! thrown away the three things a user needs: which stage failed, whether trying again could work, and how many times
//! it has been tried. All three are in [`Failed`], and the state is only left deliberately — by a retry, or by the
//! user abandoning the install.
//!
//! # Cancel, timeout and error are the same move
//!
//! Every state that is *doing* something can fail, and the three ways it fails arrive as one transition because
//! nothing downstream distinguishes them: what a caller does about a cancelled download and a timed-out one is the
//! same, and the sentence in [`Failed::detail`] is what tells a user which happened.

mod data;
mod moves;
mod source;
mod slot;
mod transition;

pub use data::{Consent, Progress, Resolved, Verified};
pub use source::{FailStage, Failed, InstallSource, WEAR_OUT_AFTER};
pub use slot::PluginSlot;
pub use moves::Move;
pub use transition::MoveError;

#[cfg(test)]
mod tests;
