//! Derives capability metadata and standalone author resources from the primary WIT contract.
//!
//! The compiler binding generators own ABI code. This tool owns the host table and trait, readable
//! report, SDK import constants and bundled SDK/CLI WIT resources. [`generate::synchronize`] prepares the
//! complete plan before writing, or checks every artifact without repairing stale files.
//! The contract parser refuses host functions without an explicit capability or ungated annotation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod bindings;
pub mod emit;
pub mod generate;
pub mod parse;

pub use bindings::{BindingError, binding_paths, emit_host_trait, emit_sdk_bindings};
pub use emit::{RenderError, emit_rust, emit_text, emitted_paths};
pub use parse::{Contract, Direction, Function, Gate, Interface, ParseError};
