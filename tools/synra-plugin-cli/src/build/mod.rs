//! Build plans choose commands and destinations; component output is staged only after Cargo succeeds.
//!
//! Rust guests compile to a core module without ambient WASI imports. Cargo's JSON metadata locates
//! the actual cdylib, including custom library names and target directories; the component encoder
//! uses the SDK's embedded WIT metadata and writes the manifest's artifact atomically.
//! Ordinary unit tests cover decisions and failures; the opt-in authoring gate builds a real scaffold.

pub(crate) mod bundle;
pub mod component;
mod plan;
mod step;
mod ui;

pub use plan::{BuildError, BuildPlan};
pub use step::Step;

/// The Rust core-module target; the SDK supplies host imports and the CLI supplies component encoding.
pub const WASM_TARGET: &str = "wasm32-unknown-unknown";

#[cfg(test)]
mod tests;

