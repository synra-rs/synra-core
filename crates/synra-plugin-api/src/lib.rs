//! The plugin contract.
//!
//! This crate is **stable**. Everything public here is something a plugin depends on, so a change is a
//! breaking change and follows the process in the stability document rather than an ordinary release.
//!
//! Three things live here:
//!
//! * [`manifest`] — what an author declares, and the checks that hold them to it.
//! * The host call surface a plugin sees, so a plugin and the kernel agree on the shape.
//! * The events a plugin receives, in the strongly typed form the host guarantees.
//!
//! What does **not** live here: the Wasm host, the loader and the instance pool. Those are the kernel's, and
//! keeping them out means a plugin author's dependency tree contains the contract and nothing else.

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

pub mod boundary;
pub mod manifest;

pub use boundary::{DeviceTarget, LogLevel, Outcome};
pub use manifest::{
    ActionDeclaration, CapabilityDeclaration, ComposeDependency, EventDeclaration, HandleDeclaration,
    HeadlessRuntime, Implementation, Manifest, ManifestContext, ManifestError, Publisher,
    ResourceHints, Runtime, SdkRequirement, UiRuntime, ValidationLevel, to_wire_slug,
};