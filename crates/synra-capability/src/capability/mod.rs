//! The capability string: parsing it, and matching one against a pattern.
//!
//! See the crate docs for the grammar and why it is shaped this way. This module is the syntax layer;
//! [`crate::set`] is the collection a plugin actually holds.
//!
//! # Why this is a directory and not a file
//!
//! Because in one file the matcher sat between a struct definition and a parsing loop, and this holds four separable
//! things: the vocabulary a capability is spelled in, the grammar that admits it, the matcher that decides whether a
//! pattern covers a candidate, and the words a consent prompt shows a user.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `segment` | a segment, and which wildcard it is |
//! | `syntax` | the limits, the errors, the type, and the parser |
//! | `matching` | whether a pattern covers a candidate, and how specific it is |
//! | `consent` | the description a user is asked to approve |

mod consent;
mod matching;
mod segment;
mod syntax;

pub use segment::Segment;
pub use syntax::{Capability, CapabilityError, MAX_LEN, MAX_PREFIX_LEN, MAX_PREFIXES, MAX_SEGMENTS};

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod tests;
