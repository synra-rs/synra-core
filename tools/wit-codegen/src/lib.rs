//! Generates the capability table from the WIT contract.
//!
//! # The problem it solves
//!
//! The host's surface — every function a plugin can call and what each one is gated on — is a fact three places need:
//! the host, which checks the gate before a call; the plugin CLI, which refuses an artifact importing a function the
//! host does not provide; and a reviewer, who wants to know that nothing is reachable without a capability.
//!
//! Written down three times, the three drift. The drift is silent in the worst direction: a function added to the host
//! and not to the table is one **any plugin can call**, and nothing in the kernel would be wrong.
//!
//! So the table is derived from `wit/synra-plugin.wit`, which is the one file the repository owns and changes
//! deliberately, and [`parse`] **refuses** a function with no gate rather than assuming one.
//!
//! # What "generated" means here
//!
//! Not Rust source: a generated `fn` per host function would be a second signature to keep in step with WIT's, and the
//! host's own code is written against a trait either way. What is generated is the *table* — a name, and the capability
//! it needs — because that is the part with no type system behind it.
//!
//! [`emit`] renders it as Rust, for the host to include, and as text, for a person to read in a review.

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
pub mod parse;

pub use bindings::{
    BindingError, binding_paths, emit_host_trait, emit_sdk_bindings,
};
pub use emit::{RenderError, emit_rust, emit_text, emitted_paths};
pub use parse::{Contract, Direction, Function, Gate, Interface, ParseError};