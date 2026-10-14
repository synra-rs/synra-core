//! Checking an artifact before it is published.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: the size and import limits, what a finding *is*, where an artifact comes
//! from, and the check itself. In one file the three hundred lines of `verify` sat below two hundred lines of type
//! definitions, so a reader changing a rule had to scroll past everything the rule produces.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `limits` | the size ceilings, and the imports a plugin may and may not use |
//! | `verdict` | a verdict, a finding, and the report they add up to |
//! | `target` | where the artifact to check comes from |
//! | `check` | the check, and the two questions it asks of a bundle |

// `check` is crate-visible so a test can ask whether one import rule covers another without building a whole
// artifact; the module itself is not part of the tool's public surface.
pub(crate) mod check;
mod limits;
mod target;
mod verdict;

#[cfg(test)]
mod tests;

pub use check::verify;
pub use limits::{MAX_UI_BYTES, MAX_UI_FILES, MAX_WASM_BYTES, PROVIDED_IMPORTS, REFUSED_IMPORTS};
pub use target::Target;
pub use verdict::{Finding, Verdict, VerifyReport};
