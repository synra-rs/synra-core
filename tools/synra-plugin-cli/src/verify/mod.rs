//! Static author checks over the actual files named by a manifest.
//!
//! Binary inspection validates nested Wasm and WIT ABI shapes without executing a guest.
//! Capability coverage uses the production host table, and never substitutes for user grants.
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | `component` | binary/WIT validation and actual import extraction |
//! | `target` | bounded artifact reads and contained UI traversal |
//! | `check` | manifest and shared capability rules expressed as findings |
//! | `limits` | artifact and traversal ceilings |
//! | `verdict` | the shared JSON and prose report |

mod check;
pub(crate) mod component;
mod limits;
mod target;
mod verdict;

#[cfg(test)]
mod tests;

pub use check::verify;
pub use component::ComponentInfo;
pub use limits::{MAX_UI_BYTES, MAX_UI_FILES, MAX_WASM_BYTES};
pub use target::Target;
pub(crate) use target::read_manifest;
pub use verdict::{Finding, Verdict, VerifyReport};
