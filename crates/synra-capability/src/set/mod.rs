//! A set of capabilities, what a plugin imports, and what it therefore may do.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds three separable things: the set itself and its display, what a plugin declares it imports, and the
//! question the kernel actually asks — do the imports and the grants add up to a coherent interface. In one file the
//! verification sat below two hundred lines of set operations, and a reader changing a rule had to scroll past the
//! storage to find it.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `limits` | the capability set, its size limits, how it renders, and why an insert was refused |
//! | `imports` | what a plugin declares it imports, and what it therefore receives |
//! | `interface` | whether the imports and the grants agree on a domain |

mod limits;
mod imports;
mod interface;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use imports::{EffectiveCaps, ImportSet};
pub use interface::{VerifyError, interface_for_domain, verify_effective_caps};
pub use limits::{CapabilitySet, MAX_CAPABILITIES, MAX_PATTERNS, SetError};
