//! What a diagnostic bundle contains, and the promise about what it never contains.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: which sections exist and which are always excluded, the records a bundle is
//! made of, the plan that assembles one, and the digest that lets a user check the file they uploaded. In one file the
//! redaction and truncation helpers — the part where a mistake leaks a secret — sat between a struct definition and a
//! hash implementation.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `sections` | which sections exist, and what is never included |
//! | `records` | the records a bundle is made of |
//! | `plan` | assembling a bundle, and the redaction passes |
//! | `digest` | the digest, and the bundle's file name |

pub mod digest;
pub mod records;
pub mod sections;

// The plan is the behaviour and it reads the other three; a file of its own is what makes the redaction helpers
// findable rather than buried between a struct and a hash.
mod plan;

pub use digest::{default_file_name, sha256_hex};
pub use plan::{BundlePlan, BundleSources, is_debug_line, is_error_line};
pub use records::{
    BundleLogLine, DeviceRecord, DiagnosticBundle, EnvSummary, LogSlice, PluginRecord,
};
pub use sections::{BundleSection, DEFAULT_LOG_TAIL_LINES, MAX_LOG_LINE_BYTES, NEVER_INCLUDED};

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod tests;